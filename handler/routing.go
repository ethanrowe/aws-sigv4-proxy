package handler

import (
	"bytes"
	"context"
	"fmt"
	"encoding/hex"
	"net/http"
	"net/http/httputil"
	"io"
	"io/ioutil"
	"regexp"
	"crypto/sha256"
	"time"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
	log "github.com/sirupsen/logrus"
)

const BODY_SHA256_HEADER = "X-Amz-Content-Sha256"

// The purpose of this type is to let us have a bytes.Reader fulfill the io.ReadCloser
// interface without losing support for the io.ReadSeeker interface.  This allows us
// to use the same structure on the request body for http.Request and aws signing.
type BodyCache struct {
	*bytes.Reader
}

func (b *BodyCache) Close() error { return nil }

func NewBodyCache(data []byte) *BodyCache {
	return &BodyCache{
		Reader: bytes.NewReader(data),
	}
}

type EndpointContextKeyType struct {}
var EndpointContextKey = &EndpointContextKeyType{}

func ReadAndHashStream(r io.Reader) (data []byte, digest string, err error) { 
	hasher := sha256.New()
	data, err = ioutil.ReadAll(io.TeeReader(r, hasher))
	if err != nil {
		return
	}
	digest = hex.EncodeToString(hasher.Sum(nil))
	return
}

func AsReadSeeker(r io.Reader) (io.ReadSeeker, error) {
	seeker, ok := r.(io.ReadSeeker)
	if ok {
		return seeker, nil
	}

	body, err := ioutil.ReadAll(r)
	if err == nil {
		seeker = NewBodyCache(body)
	}
	return seeker, err
}

func GetServiceEndpoint(r *http.Request) endpoints.ResolvedEndpoint {
	return r.Context().Value(EndpointContextKey).(endpoints.ResolvedEndpoint)
}

func WithServiceEndpoint(r *http.Request, endpoint endpoints.ResolvedEndpoint) *http.Request {
	return r.WithContext(
		context.WithValue(
			r.Context(),
			EndpointContextKey,
			endpoint,
		),
	)
}

type OriginalRequestHeadersKeyType struct {}
var OriginalRequestHeadersKey = &OriginalRequestHeadersKeyType{}

func GetOriginalRequestHeaders(r *http.Request) http.Header {
	return r.Context().Value(OriginalRequestHeadersKey).(http.Header)
}

func WithOriginalRequestHeaders(r *http.Request) *http.Request {
	return r.WithContext(
		context.WithValue(
			r.Context(),
			OriginalRequestHeadersKey,
			r.Header,
		),
	)
}

// binds the request context to the specified ResolvedEndpoint 
func EndpointContextHandler(endpoint endpoints.ResolvedEndpoint, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("EndpointContextHandler!")
		next.ServeHTTP(w, WithServiceEndpoint(r, endpoint))
	})
}

// replaces original request with a copy of the URI and body,
// and preserves the original headers in the context.
func CreateProxyRequestHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := *r.URL
		url.Host = r.Host
		url.Scheme = "https"
		newReq, err := http.NewRequest(r.Method, url.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		newReq = newReq.WithContext(
			context.WithValue(
				r.Context(),
				OriginalRequestHeadersKey,
				r.Header,
			),
		)
		newReq.ContentLength = r.ContentLength

		if sha := r.Header.Get(BODY_SHA256_HEADER); sha != "" {
			newReq.Header.Set(BODY_SHA256_HEADER, sha)
		}

		next.ServeHTTP(w, newReq)
	})
}

// merge the original headers from context back into the
// request.
func RestoreHeadersWithoutOverwriteHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		copyHeaderWithoutOverwrite(r.Header, GetOriginalRequestHeaders(r))
		next.ServeHTTP(w, r)
	})
}

// sign the request
func Sigv4SignHandler(signer *v4.Signer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ep := GetServiceEndpoint(r)
		seeker, err := AsReadSeeker(r.Body)
		if err != nil {
			log.WithError(err).Error("Failed to convert body to ReadSeeker for signing")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = signer.Sign(r, seeker, ep.SigningName, ep.SigningRegion, time.Now())

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		seeker.Seek(0, io.SeekStart)
		closer, ok := seeker.(io.ReadCloser)
		if ok {
			r.Body = closer
		}

		next.ServeHTTP(w, r)
	})
}

// presign the request
func Sigv4PresignHandler(signer *v4.Signer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ep := GetServiceEndpoint(r)
		seeker, err := AsReadSeeker(r.Body)
		if err != nil {
			log.WithError(err).Error("Failed to convert body to ReadSeeker for signing")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = signer.Presign(r, seeker, ep.SigningName, ep.SigningRegion, time.Duration(time.Hour), time.Now())

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		seeker.Seek(0, io.SeekStart)
		closer, ok := seeker.(io.ReadCloser)
		if ok {
			r.Body = closer
		}

		next.ServeHTTP(w, r)
	})
}

// strip the specified headers off of the request object
// before passing along to next handler
func StripHeaderHandler(headers []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := log.WithField("handler", "StripHeaderHandler")
		for _, header := range headers {
			logger.WithField("header", header).Debug("strip.")
			r.Header.Del(header)
		}
		next.ServeHTTP(w, r)
	})
}

// Actually issue the request and delegate response to it.
// Assumes the request passed in is structured for proxying (as opposed
// to the original request received by the server)
func DoProxyRequestHandler(client Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if log.GetLevel() == log.DebugLevel {
			logger := log.WithField("handler", "DoProxyRequestHandler")
			dump, err := httputil.DumpRequest(r, false)
			if err != nil {
				logger.WithError(err).Error("Unable to dump request")
			} else {
				logger.WithField("request", string(dump)).Debug("proxying request")
			}
		}

		resp, err := client.Do(r)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		defer resp.Body.Close()

		// read response body
		buf := bytes.Buffer{}
		if _, err := io.Copy(&buf, resp.Body); err != nil {
			log.WithError(err).Error("unable to proxy request")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// copy headers
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(resp.StatusCode)
		w.Write(buf.Bytes())
	})
}

// canonicalizes request URL raw path according to AWS-style escaping
func CanonicalizeRawPathHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("CanonicalizeRawPathHandler!")
		r.URL.RawPath = EscapePath(r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// canonicalize request URL raw path *segments* (do not escape the path
// separators) accroding to AWS-style escaping
func CanonicalizeRawPathSegmentsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("CanonicalizeRawPathSegmentsHandler!")
		r.URL.RawPath = EscapePathSegments(r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func LogMessageHandler(msg string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.WithField("URL", r.URL.String()).
		  WithField("method", r.Method).
			WithField("host", r.Host).
			Info(msg)
		next.ServeHTTP(w, r)
	})
}

func LogServiceHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ep := GetServiceEndpoint(r)
		log.WithField("handler", "LogServiceHandler").
		  WithField("endpoint", ep.URL).
		  WithField("signingName", ep.SigningName).
			WithField("signingRegion", ep.SigningRegion).
			WithField("signingMethod", ep.SigningMethod).
		  Info("service endpoint")
		next.ServeHTTP(w, r)
	})
}

func FullBodyReadHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		l := log.WithField("handler", "FullBodyReadHandler")
		// Only care about the full-body read if it's a put or a post
		if (method == http.MethodPut) || (method == http.MethodPost) {
			l.WithField("method", method).Debug("checking headers")
			// Determine if we have an indeterminate body length or a 100-continue expectation
			// (typically both)
			if (r.Header.Get("Expect") != "") || (r.ContentLength < 0) {
				l.WithField("ContentLengthHeader", r.Header.Get("Content-Length")).WithField("ContentLengthField", r.ContentLength).Debug("caching body")
				// If content length was unspecified in the headers and there's no transfer encoding, the content length
				// will default to 0; the Expect header must be present and the client may be waiting for 100-continue.
				// But the net/http stack won't auto-send the 100-continue line with content length 0.
				// We're supporting this non-standard behavior for S3 in particular.
				if r.ContentLength == 0 {
				  // l.Info("Forcing non-standard HTTP/1.1 100 Continue")
					// This would require connection hijack, which let's not do unless we have to.
				  // w.WriteString("HTTP/1.1 100 Continue\r\n\r\n")
					// w.Flush()
					log.WithField("ContentLength", r.ContentLength).WithField("Expect", r.Header.Get("Expect")).
					  Warn("Invalid content-length/transfer-encoding/expect combination")
					http.Error(w, "Invalid content-length/transfer-encoding/expect combination", http.StatusBadRequest)
					return
				}
				data, hashdigest, err := ReadAndHashStream(r.Body)
				if err != nil {
					l.WithError(err).Error("Failed caching body for FullBodyReadHandler")
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				log.Debug("read the body")

				r.Body = NewBodyCache(data)
				r.ContentLength = int64(len(data))
				r.TransferEncoding = make([]string, 0, 0)
				r.Header.Del("Expect")
				r.Header.Set(BODY_SHA256_HEADER, hashdigest)
				l.WithField("ContentLength", r.ContentLength).
				  WithField(BODY_SHA256_HEADER, hashdigest).
					Info("FullBodyReadHandler cached body before proxying")
			}
		}
		next.ServeHTTP(w, r)
	})
}

func S3SignHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "S3SignHandler for endpoint", GetServiceEndpoint(r))

	})
}

func DefaultSignHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "DefaultSignHandler for endpoint", GetServiceEndpoint(r))
	})
}

func RegexpEndpointRoutingHandler(pattern string, next, nomatch http.Handler) http.Handler {
	re := regexp.MustCompile(pattern)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		matches := re.FindStringSubmatch(r.Host)
		var service endpoints.ResolvedEndpoint

		if matches != nil {
			service = services[matches[1]]
		}

		if service.URL == "" {
			nomatch.ServeHTTP(w, r)
		} else {
			next.ServeHTTP(w, WithServiceEndpoint(r, services[matches[1]]))
		}
	})
}

func BuildRouter(p *ProxyClient) http.Handler {
	mux := &http.ServeMux{}

	for hostname, resolvedEndpoint := range services {
		hostpath := hostname + "/"
		log.Debug("Adding route for hostname: " + hostpath)
		switch resolvedEndpoint.SigningName {
		case "s3":
			mux.Handle(
				hostpath,
				LogMessageHandler(
					"s3 route entered",
					EndpointContextHandler(
						resolvedEndpoint,
						LogServiceHandler(
							CanonicalizeRawPathSegmentsHandler(
								FullBodyReadHandler(S3SignHandler()),
							),
						),
					),
				),
			)
			break
		default:
			mux.Handle(
				hostpath,
				LogMessageHandler(
					"general AWS route entered",
					EndpointContextHandler(
						resolvedEndpoint,
						LogServiceHandler(DefaultSignHandler()),
					),
				),
			)
			break
		}
	}

	return RegexpEndpointRoutingHandler(
		"^(?:[^.]+\\.)?(s3\\.(?:[-a-z0-9]+\\.)?amazonaws\\.com(?:\\.cn)?)$",
		LogMessageHandler(
			"s3 regexp route entered",
			LogServiceHandler(
				CanonicalizeRawPathSegmentsHandler(
					FullBodyReadHandler(
						CreateProxyRequestHandler(
							Sigv4PresignHandler(
								p.S3Signer,
								RestoreHeadersWithoutOverwriteHandler(
									DoProxyRequestHandler(p.Client),
								),
							),
						),
					),
				),
			),
		),
		mux,
	)
}

