package oauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"mime/multipart"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type OAuthConsumer struct {
	Service          string
	RequestTokenURL  string
	AccessTokenURL   string
	AuthorizationURL string
	ConsumerKey      string
	ConsumerSecret   string
	CallBackURL      string
	UserAgent        string
	Timeout          int64
	requestTokens    []*RequestToken
	AdditionalParams Params
}

// GetRequestAuthorizationURL Returns the URL for the visitor to Authorize the Access
func (oc *OAuthConsumer) GetRequestAuthorizationURL() (string, *RequestToken, error) {
	// Gather the params
	p := Params{}

	// Add required OAuth params
	p.Add(&Pair{Key: "oauth_version", Value: "1.0"})
	p.Add(&Pair{Key: "oauth_timestamp", Value: strconv.FormatInt(time.Now().Unix(), 10)})
	p.Add(&Pair{Key: "oauth_consumer_key", Value: oc.ConsumerKey})
	p.Add(&Pair{Key: "oauth_callback", Value: oc.CallBackURL})
	nounce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return "", nil, err
	}
	p.Add(&Pair{Key: "oauth_nonce", Value: nounce.String()})
	p.Add(&Pair{Key: "oauth_signature_method", Value: "HMAC-SHA1"})

	// Sort the collection
	sort.Sort(p)

	// Generate string of sorted params
	sigBaseCol := make([]string, len(p)+len(oc.AdditionalParams))
	for i := range p {
		sigBaseCol[i] = Encode(p[i].Key) + "=" + Encode(p[i].Value)
	}

	buf := &bytes.Buffer{}

	i := len(p)
	for _, kv := range oc.AdditionalParams {
		buf.Write([]byte(kv.Key + "=" + Encode(kv.Value) + ""))
		sigBaseCol[i] = kv.Key + "=" + Encode(kv.Value)
		i++
	}

	sigBaseStr := "GET&" +
		Encode(oc.RequestTokenURL) + "&" +
		Encode(strings.Join(sigBaseCol, "&"))

		// Generate Composite Signing key
	key := Encode(oc.ConsumerSecret) + "&" + "" // token secrect is blank on the Request Token

	// Generate Signature
	d := oc.digest(key, sigBaseStr)

	// Build Auth Header
	authHeader := "OAuth "
	for i := range p {
		authHeader += p[i].Key + "=\"" + Encode(p[i].Value) + "\", "
	}

	// Add the signature
	authHeader += "oauth_signature=\"" + Encode(d) + "\""

	headers := map[string]string{
		"Content-Type":  "text/plain",
		"Authorization": authHeader,
		"User-Agent":    oc.UserAgent,
	}

	lAddParams := len(oc.AdditionalParams)
	if lAddParams > 0 {
		oc.RequestTokenURL += "?" + string(buf.Bytes())
	}

	r, err := get(oc.RequestTokenURL, headers, oc.Timeout)

	if err != nil {
		return "", nil, err
	}

	if r.StatusCode != 200 {
		// OAuth service returned an error
		return "", nil, errors.New("OAuth Service returned an error : " + r.Status)
	}

	b, _ := ioutil.ReadAll(r.Body)
	s := string(b)

	rt := &RequestToken{}

	if strings.Index(s, "&") == -1 {
		// Body is empty 
		return "", nil, errors.New("Empty response from server")
	}

	vals := strings.SplitN(s, "&", 10)

	for i := range vals {
		if strings.Index(vals[i], "=") > -1 {
			kv := strings.SplitN(vals[i], "=", 2)
			if len(kv) > 0 { // Adds the key even if there's no value. 
				switch kv[0] {
				case "oauth_token":
					if len(kv) > 1 {
						rt.Token = kv[1]
					}
					break
				case "oauth_token_secret":
					if len(kv) > 1 {
						rt.Secret = kv[1]
					}
					break
				}
			}
		}
	}

	oc.appendRequestToken(rt)

	return oc.AuthorizationURL + "?oauth_token=" + rt.Token, rt, nil

}

// GetAccessToken gets the access token for the response from the Authorization URL
func (oc *OAuthConsumer) GetAccessToken(token string, verifier string) *AccessToken {
	var rt *RequestToken

	// Match the RequestToken by Token
	for i := range oc.requestTokens {
		if oc.requestTokens[i].Token == token ||
			oc.requestTokens[i].Token == Encode(token) {
			rt = oc.requestTokens[i]
		}
	}

	rt.Verifier = verifier

	// Gather the params
	p := Params{}

	// Add required OAuth params
	p.Add(&Pair{Key: "oauth_consumer_key", Value: oc.ConsumerKey})
	p.Add(&Pair{Key: "oauth_token", Value: rt.Token})
	p.Add(&Pair{Key: "oauth_verifier", Value: rt.Verifier})
	p.Add(&Pair{Key: "oauth_signature_method", Value: "HMAC-SHA1"})
	p.Add(&Pair{Key: "oauth_timestamp", Value: strconv.FormatInt(time.Now().Unix(), 10)})
	nounce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil
	}
	p.Add(&Pair{Key: "oauth_nonce", Value: nounce.String()})
	p.Add(&Pair{Key: "oauth_version", Value: "1.0"})

	// Sort the collection
	sort.Sort(p)

	// Generate string of sorted params
	sigBaseCol := make([]string, len(p))
	for i := range p {
		sigBaseCol[i] = Encode(p[i].Key) + "=" + Encode(p[i].Value)
	}

	sigBaseStr := "POST&" +
		Encode(oc.AccessTokenURL) + "&" +
		Encode(strings.Join(sigBaseCol, "&"))

	sigBaseStr = strings.Replace(sigBaseStr, Encode(Encode(rt.Token)), Encode(rt.Token), 1)

	// Generate Composite Signing key
	key := Encode(oc.ConsumerSecret) + "&" + rt.Secret

	// Generate Signature
	d := oc.digest(key, sigBaseStr)

	// Build Auth Header
	authHeader := "OAuth "
	for i := range p {
		authHeader += p[i].Key + "=\"" + Encode(p[i].Value) + "\", "
	}

	// Add the signature
	authHeader += "oauth_signature=\"" + Encode(d) + "\""

	authHeader = strings.Replace(authHeader, Encode(rt.Token), rt.Token, 1)

	// Add Header & Buffer for params
	buf := &bytes.Buffer{}
	headers := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": authHeader,
		"User-Agent":    oc.UserAgent,
	}

	// Action the POST to get the AccessToken
	r, err := post(oc.AccessTokenURL, headers, buf, oc.Timeout, buf.Len())

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	// Read response Body & Create AccessToken
	b, _ := ioutil.ReadAll(r.Body)
	s := string(b)
	at := &AccessToken{Service: oc.Service}

	if strings.Index(s, "&") > -1 {
		vals := strings.SplitN(s, "&", 10)

		for i := range vals {
			if strings.Index(vals[i], "=") > -1 {
				kv := strings.SplitN(vals[i], "=", 2)
				if len(kv) > 0 { // Adds the key even if there's no value. 
					switch kv[0] {
					case "oauth_token":
						if len(kv) > 1 {
							at.Token = kv[1]
						}
						break
					case "oauth_token_secret":
						if len(kv) > 1 {
							at.Secret = kv[1]
						}
						break
					}
				}
			}
		}
	}

	// Return the AccessToken
	return at

}

// OAuthRequestGet return the response via a GET for the url with the AccessToken passed
func (oc *OAuthConsumer) Get(url string, fparams Params, at *AccessToken) (r *http.Response, err error) {
	return oc.oAuthRequest(url, fparams, at, "GET")
}

// OAuthRequest returns the response via a POST for the url with the AccessToken passed & the Form params passsed in fparams
func (oc *OAuthConsumer) Post(url string, fparams Params, at *AccessToken) (r *http.Response, err error) {
	return oc.oAuthRequest(url, fparams, at, "POST")
}

type PostFileContent struct {
	Name   string
	Reader io.Reader
}

func (oc *OAuthConsumer) PostFile(url string, fparams Params, files map[string]PostFileContent, at *AccessToken) (r *http.Response, err error) {

	// Gather the params
	p := fparams

	hp := Params{}

	// Add required OAuth params
	p.Add(&Pair{Key: "oauth_token", Value: at.Token})
	p.Add(&Pair{Key: "oauth_signature_method", Value: "HMAC-SHA1"})
	p.Add(&Pair{Key: "oauth_consumer_key", Value: oc.ConsumerKey})
	p.Add(&Pair{Key: "oauth_timestamp", Value: strconv.FormatInt(time.Now().Unix(), 10)})
	nounce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	p.Add(&Pair{Key: "oauth_nonce", Value: nounce.String()})
	p.Add(&Pair{Key: "oauth_version", Value: "1.0"})

	// Add the params to the Header collection
	for i := range p {
		hp.Add(&Pair{Key: p[i].Key, Value: p[i].Value})
	}

	// Sort the collection
	sort.Sort(p)

	// Generate string of sorted params
	sigBaseCol := make([]string, len(p)+len(fparams))
	for i := range p {
		sigBaseCol[i] = Encode(p[i].Key) + "=" + Encode(p[i].Value)
	}

	sigBaseStr := "POST" + "&" +
		Encode(url) + "&"

	temp := ""
	for i := range sigBaseCol {
		temp += sigBaseCol[i]
		if i < len(sigBaseCol)-2 {
			temp += "&"
		}
	}

	sigBaseStr = sigBaseStr + Encode(temp)

	sigBaseStr = strings.Replace(sigBaseStr, Encode(Encode(at.Token)), Encode(at.Token), 1)

	// Generate Composite Signing key
	key := Encode(oc.ConsumerSecret) + "&" + at.Secret

	// Generate Signature
	d := oc.digest(key, sigBaseStr)
	// Build Auth Header
	authHeader := "OAuth "
	for i := range hp {
		if strings.Index(hp[i].Key, "oauth") == 0 {
			//Add it to the authHeader
			authHeader += hp[i].Key + "=\"" + Encode(hp[i].Value) + "\", "
		}
	}

	// Add the signature
	authHeader += "oauth_signature=\"" + Encode(d) + "\""

	authHeader = strings.Replace(authHeader, Encode(at.Token), at.Token, 1)
	// Add Header & Buffer for params

	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)

	for i := range fparams {
		k, v := fparams[i].Key, fparams[i].Value
		ff, err := w.CreateFormField(k)
		if err != nil {
			return nil, err
		}
		ff.Write([]byte(v))
	}

	for k, v := range files {
		fw, err := w.CreateFormFile(k, v.Name)
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(fw, v.Reader)
		if err != nil {
			return nil, err
		}
	}
	w.Close()

	headers := map[string]string{
		"Authorization": authHeader,
		"User-Agent":    oc.UserAgent,
		"Content-Type":  w.FormDataContentType(),
	}

	// return POSTs response
	return post(url, headers, buf, oc.Timeout, buf.Len())

}

func (oc *OAuthConsumer) oAuthRequest(url string, fparams Params, at *AccessToken, method string) (r *http.Response, err error) {

	// Gather the params
	p := Params{}

	hp := Params{}

	// Add required OAuth params
	p.Add(&Pair{Key: "oauth_token", Value: at.Token})
	p.Add(&Pair{Key: "oauth_signature_method", Value: "HMAC-SHA1"})
	p.Add(&Pair{Key: "oauth_consumer_key", Value: oc.ConsumerKey})
	p.Add(&Pair{Key: "oauth_timestamp", Value: strconv.FormatInt(time.Now().Unix(), 10)})
	nounce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}

	p.Add(&Pair{Key: "oauth_nonce", Value: nounce.String()})
	p.Add(&Pair{Key: "oauth_version", Value: "1.0"})

	// Add the params to the Header collection
	for i := range p {
		hp.Add(&Pair{Key: p[i].Key, Value: p[i].Value})
	}

	fplist := make([]string, 0)
	// Add any additional params passed
	for i := range fparams {
		k, v := fparams[i].Key, fparams[i].Value
		p.Add(&Pair{Key: k, Value: v})
		fplist = append(fplist, k+"="+Encode(v))
	}
	fparamsStr := strings.Join(fplist, "&")

	// Sort the collection
	sort.Sort(p)

	// Generate string of sorted params
	sigBaseCol := make([]string, len(p))
	for i := range p {
		sigBaseCol[i] = Encode(p[i].Key) + "=" + Encode(p[i].Value)
	}

	sigBaseStr := method + "&" +
		Encode(url) + "&" +
		Encode(strings.Join(sigBaseCol, "&"))

	sigBaseStr = strings.Replace(sigBaseStr, Encode(Encode(at.Token)), Encode(at.Token), 1)

	// Generate Composite Signing key
	key := Encode(oc.ConsumerSecret) + "&" + at.Secret

	// Generate Signature
	d := oc.digest(key, sigBaseStr)

	// Add the signature
	hp.Add(&Pair{Key: "oauth_signature", Value: d})
	sort.Sort(hp)

	// Build Auth Header
	authHeaders := make([]string, 0)
	for i := range hp {
		if strings.Index(hp[i].Key, "oauth") == 0 {
			//Add it to the authHeader
			authHeaders = append(authHeaders, hp[i].Key+"=\""+Encode(hp[i].Value)+"\"")
		}
	}
	authHeader := "OAuth " + strings.Join(authHeaders, ", ")

	authHeader = strings.Replace(authHeader, Encode(at.Token), at.Token, 1)

	// Add Header & Buffer for params
	buf := bytes.NewBufferString(fparamsStr)
	headers := map[string]string{
		"Authorization": authHeader,
		"User-Agent":    oc.UserAgent,
	}

	if method == "GET" {
		// return Get response
		return get(url+"?"+fparamsStr, headers, oc.Timeout)
	}

	headers["Content-Type"] = "application/x-www-form-urlencoded"
	// return POSTs response
	return post(url, headers, buf, oc.Timeout, buf.Len())

}

// digest Generates a HMAC-1234 for the signature
func (oc *OAuthConsumer) digest(key string, m string) string {
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(m))
	return base64encode(h.Sum(nil))

	/*	s := bytes.TrimSpace(h.Sum())
		d := make([]byte, base64.StdEncoding.EncodedLen(len(s)))
		base64.StdEncoding.Encode(d, s)
		ds := strings.TrimSpace(bytes.NewBuffer(d).String())
	*/
	//	return ds

}

// appendRequestToken adds the Request Tokens to a localy temp collection
func (oc *OAuthConsumer) appendRequestToken(token *RequestToken) {

	if oc.requestTokens == nil {
		oc.requestTokens = make([]*RequestToken, 0, 4)
	}

	n := len(oc.requestTokens)

	if n+1 > cap(oc.requestTokens) {
		s := make([]*RequestToken, n, 2*n+1)
		copy(s, oc.requestTokens)
		oc.requestTokens = s
	}
	oc.requestTokens = oc.requestTokens[0 : n+1]
	oc.requestTokens[n] = token

}
