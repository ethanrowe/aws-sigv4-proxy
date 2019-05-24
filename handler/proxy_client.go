package handler

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
	log "github.com/sirupsen/logrus"
)

// Unique context key type for header stripping control
type RequestHeadersToStripType struct {}
var RequestHeadersToStripKey = &RequestHeadersToStripType{}

// Helper function for setting headers to strip
func SetStripHeaders(ctx context.Context, h []string) context.Context {
	return context.WithValue(ctx, RequestHeadersToStripKey, h)
}

// Helper function for retrieving headers to strip
func GetStripHeaders(ctx context.Context) []string {
	return ctx.Value(RequestHeadersToStripKey).([]string)
}

// Client is an interface to make testing http.Client calls easier
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// ProxyClient implements the Client interface
type ProxyClient struct {
	Signer *v4.Signer
	S3Signer *v4.Signer
	Client Client
	Region string
	StripRequestHeaders []string
}

func (p *ProxyClient) PrepareRequestContext(req *http.Request) *http.Request {
	return req.WithContext(SetStripHeaders(req.Context(), p.StripRequestHeaders))
}

func (p *ProxyClient) sign(req *http.Request, service *endpoints.ResolvedEndpoint) (*http.Request, error) {
	body := bytes.NewReader([]byte{})

	if req.Body != nil {
		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return req, err
		}

		req.ContentLength = int64(len(b))
		body = bytes.NewReader(b)
	}

	var err error
	switch service.SigningMethod {
	case "v4", "s3v4":
		_, err = p.Signer.Sign(req, body, service.SigningName, service.SigningRegion, time.Now())
		break
	case "s3":
		// The s3 case wants the path separators preserved in escaping.
		req.URL.RawPath = EscapePathSegments(req.URL.Path)
		switch req.Method {
		case http.MethodPut, http.MethodPost:
			req = req.WithContext(SetStripHeaders(req.Context(), append(p.StripRequestHeaders, "Expect")))
			_, err = p.S3Signer.Sign(req, body, service.SigningName, service.SigningRegion, time.Now())
		default:
			_, err = p.S3Signer.Presign(req, body, service.SigningName, service.SigningRegion, time.Duration(time.Hour), time.Now())
		}
		break
	default:
		err = fmt.Errorf("unable to sign with specified signing method %s for service %s", service.SigningMethod, service.SigningName)
		break
	}

	if err == nil {
		log.WithFields(log.Fields{"service": service.SigningName, "region": service.SigningRegion}).Debug("signed request")
	}

	return req, err
}

func copyHeaderWithoutOverwrite(dst, src http.Header) {
	for k, vv := range src {
		if _, ok := dst[k]; !ok {
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
	}
}

func (p *ProxyClient) Do(req *http.Request) (*http.Response, error) {
	proxyURL := *req.URL
	proxyURL.Host = req.Host
	proxyURL.Scheme = "https"

	if log.GetLevel() == log.DebugLevel {
		initialReqDump, err := httputil.DumpRequest(req, false)
		if err != nil {
			log.WithError(err).Error("unable to dump request")
		}
		log.WithField("request", string(initialReqDump)).Debug("Initial request dump:")
	}

	proxyReq, err := http.NewRequest(req.Method, proxyURL.String(), req.Body)
	if err != nil {
		return nil, err
	}
	proxyReq = p.PrepareRequestContext(proxyReq)

	service := determineAWSServiceFromHost(req.Host)
	if service == nil {
		return nil, fmt.Errorf("unable to determine service from host: %s", req.Host)
	}

	proxyReq, err = p.sign(proxyReq, service)
	if err != nil {
		return nil, err
	}

	// Hack for PUT to S3.
	// Replace original request body because we read it from the proxy.
	req.Body = proxyReq.Body
	if req.Body != nil {
		log.WithField("Content-Length", string(proxyReq.ContentLength)).Debug("Setting content-length on request")
		req.ContentLength = proxyReq.ContentLength
	}

	// Remove any headers specified
	for _, header := range GetStripHeaders(proxyReq.Context()) {
		log.WithField("StripHeader", string(header)).Debug("Stripping Header:")
		req.Header.Del(header)
	}

	// Add origin headers after request is signed (no overwrite)
	copyHeaderWithoutOverwrite(proxyReq.Header, req.Header)

	if log.GetLevel() == log.DebugLevel {
		proxyReqDump, err := httputil.DumpRequest(proxyReq, false)
		if err != nil {
			log.WithError(err).Error("unable to dump request")
		}
		log.WithField("request", string(proxyReqDump)).Debug("proxying request")
	}

	resp, err := p.Client.Do(proxyReq)
	if err != nil {
		return nil, err
	}

	if log.GetLevel() == log.DebugLevel && resp.StatusCode >= 400 {
		b, _ := ioutil.ReadAll(resp.Body)
		log.WithField("message", string(b)).Error("error proxying request")
	}

	return resp, nil
}
