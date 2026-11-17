package spnego

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/test"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestClient_SetSPNEGOHeader(t *testing.T) {
	test.Integration(t)
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	l := log.New(os.Stderr, "SPNEGO Client:", log.LstdFlags)
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c, client.Logger(l))

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on AS_REQ: %v\n", err)
	}
	urls := []string{
		"http://cname.test.gokrb5",
		"http://host.test.gokrb5",
	}
	paths := []string{
		"/modkerb/index.html",
		//"/modgssapi/index.html",
	}
	for _, url := range urls {
		for _, p := range paths {
			r, _ := http.NewRequest("GET", url+p, nil)
			httpResp, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatalf("%s request error: %v", url+p, err)
			}
			assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")

			err = SetSPNEGOHeader(cl, r, "")
			if err != nil {
				t.Fatalf("error setting client SPNEGO header: %v", err)
			}

			httpResp, err = http.DefaultClient.Do(r)
			if err != nil {
				t.Fatalf("%s request error: %v\n", url+p, err)
			}
			assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
		}
	}
}

func TestSPNEGOHTTPClient(t *testing.T) {
	test.Integration(t)
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	l := log.New(os.Stderr, "SPNEGO Client:", log.LstdFlags)
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c, client.Logger(l))

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on AS_REQ: %v\n", err)
	}
	urls := []string{
		"http://cname.test.gokrb5",
		"http://host.test.gokrb5",
	}
	// This path issues a redirect which the http client will automatically follow.
	// It should cause a replay issue if the negInit token is sent in the first instance.
	paths := []string{
		"/modgssapi", // This issues a redirect which the http client will automatically follow. Could cause a replay issue
		"/redirect",
	}
	for _, url := range urls {
		for _, p := range paths {
			r, _ := http.NewRequest("GET", url+p, nil)
			httpCl := http.DefaultClient
			httpCl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				t.Logf("http client redirect: %+v", *req)
				return nil
			}
			spnegoCl := NewClient(cl, httpCl, "")
			httpResp, err := spnegoCl.Do(r)
			if err != nil {
				t.Fatalf("%s request error: %v", url+p, err)
			}
			assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
		}
	}
}

func TestService_SPNEGOKRB_NoAuthHeader(t *testing.T) {
	s := httpServer()
	defer s.Close()
	r, _ := http.NewRequest("GET", s.URL, nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")
	assert.Equal(t, "Negotiate", httpResp.Header.Get("WWW-Authenticate"), "Negotiation header not set by server.")
}

func TestService_SPNEGOKRB_ValidUser(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()
	r, _ := http.NewRequest("GET", s.URL, nil)

	cl := getClient()
	err := SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
}

func TestService_SPNEGOKRB_ValidUser_RawKRB5Token(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()
	r, _ := http.NewRequest("GET", s.URL, nil)

	cl := getClient()
	sc := SPNEGOClient(cl, "HTTP/host.test.gokrb5")
	err := sc.AcquireCred()
	if err != nil {
		t.Fatalf("could not acquire client credential: %v", err)
	}
	st, err := sc.InitSecContext()
	if err != nil {
		t.Fatalf("could not initialize context: %v", err)
	}

	// Use the raw KRB5 context token
	nb := st.(*SPNEGOToken).NegTokenInit.MechTokenBytes
	hs := "Negotiate " + base64.StdEncoding.EncodeToString(nb)
	r.Header.Set(HTTPHeaderAuthRequest, hs)

	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
}

func TestService_SPNEGOKRB_Replay(t *testing.T) {
	test.Integration(t)

	s := httpServerWithoutSessionManager()
	defer s.Close()
	r1, _ := http.NewRequest("GET", s.URL, nil)

	cl := getClient()
	err := SetSPNEGOHeader(cl, r1, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	// First request with this ticket should be accepted
	httpResp, err := http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")

	// Use ticket again should be rejected
	httpResp, err = http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")

	// Form a 2nd ticket
	r2, _ := http.NewRequest("GET", s.URL, nil)

	err = SetSPNEGOHeader(cl, r2, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	// First use of 2nd ticket should be accepted
	httpResp, err = http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")

	// Using the 1st ticket again should still be rejected
	httpResp, err = http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")

	// Using the 2nd again should be rejected as replay
	httpResp, err = http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")
}

func TestService_SPNEGOKRB_ReplayCache_Concurrency(t *testing.T) {
	test.Integration(t)

	s := httpServerWithoutSessionManager()
	defer s.Close()
	r1, _ := http.NewRequest("GET", s.URL, nil)

	cl := getClient()
	err := SetSPNEGOHeader(cl, r1, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}
	r1h := r1.Header.Get(HTTPHeaderAuthRequest)

	r2, _ := http.NewRequest("GET", s.URL, nil)

	err = SetSPNEGOHeader(cl, r2, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}
	r2h := r2.Header.Get(HTTPHeaderAuthRequest)

	// Concurrent 1st requests should be OK
	var wg sync.WaitGroup
	wg.Add(2)
	go httpGet(r1, &wg)
	go httpGet(r2, &wg)
	wg.Wait()

	// A number of concurrent requests with the same ticket should be rejected due to replay
	var wg2 sync.WaitGroup
	noReq := 10
	wg2.Add(noReq * 2)
	for i := 0; i < noReq; i++ {
		rr1, _ := http.NewRequest("GET", s.URL, nil)
		rr1.Header.Set(HTTPHeaderAuthRequest, r1h)
		rr2, _ := http.NewRequest("GET", s.URL, nil)
		rr2.Header.Set(HTTPHeaderAuthRequest, r2h)
		go httpGet(rr1, &wg2)
		go httpGet(rr2, &wg2)
	}
	wg2.Wait()
}

func TestService_SPNEGOKRB_Upload(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("uploadfile", "testfile.bin")
	if err != nil {
		t.Fatalf("error writing to buffer: %v", err)
	}

	data := make([]byte, 10240)
	rand.Read(data)
	br := bytes.NewReader(data)
	_, err = io.Copy(fileWriter, br)
	if err != nil {
		t.Fatalf("error copying bytes: %v", err)
	}
	bodyWriter.Close()

	r, _ := http.NewRequest("POST", s.URL, bodyBuf)
	r.Header.Set("Content-Type", bodyWriter.FormDataContentType())

	cl := getClient()
	cookieJar, _ := cookiejar.New(nil)
	httpCl := http.DefaultClient
	httpCl.Jar = cookieJar
	spnegoCl := NewClient(cl, httpCl, "HTTP/host.test.gokrb5")
	httpResp, err := spnegoCl.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		bodyString := string(bodyBytes)
		httpResp.Body.Close()
		t.Errorf("unexpected code from http server (%d): %s", httpResp.StatusCode, bodyString)
	}
}

func httpGet(r *http.Request, wg *sync.WaitGroup) {
	defer wg.Done()
	http.DefaultClient.Do(r)
}

func httpServerWithoutSessionManager() *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.LstdFlags)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(SPNEGOKRB5Authenticate(th, kt, service.Logger(l)))
	return s
}

func httpServer() *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.LstdFlags)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(SPNEGOKRB5Authenticate(th, kt, service.Logger(l), service.SessionManager(NewSessionMgr("gokrb5"))))
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		maxUploadSize := int64(11240)
		if err := r.ParseMultipartForm(maxUploadSize); err != nil {
			http.Error(w, fmt.Sprintf("cannot parse multipart form: %v", err), http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
		file, _, err := r.FormFile("uploadfile")
		if err != nil {
			http.Error(w, "INVALID_FILE", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// write out to /dev/null
		_, err = io.Copy(io.Discard, file)
		if err != nil {
			http.Error(w, "WRITE_ERR", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	id := goidentity.FromHTTPRequestContext(r)
	fmt.Fprintf(w, "<html>\nTEST.GOKRB5 Handler\nAuthenticed user: %s\nUser's realm: %s\n</html>",
		id.UserName(),
		id.Domain())
	return
}

func getClient() *client.Client {
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.LibDefaults.NoAddresses = true
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.Realms[0].KPasswdServer = []string{addr + ":464"}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	return cl
}

type SessionMgr struct {
	skey       []byte
	store      sessions.Store
	cookieName string
}

func NewSessionMgr(cookieName string) SessionMgr {
	skey := []byte("thisistestsecret") // Best practice is to load this key from a secure location.
	return SessionMgr{
		skey:       skey,
		store:      sessions.NewCookieStore(skey),
		cookieName: cookieName,
	}
}

func (smgr SessionMgr) Get(r *http.Request, k string) ([]byte, error) {
	s, err := smgr.store.Get(r, smgr.cookieName)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errors.New("nil session")
	}
	b, ok := s.Values[k].([]byte)
	if !ok {
		return nil, fmt.Errorf("could not get bytes held in session at %s", k)
	}
	return b, nil
}

func (smgr SessionMgr) New(w http.ResponseWriter, r *http.Request, k string, v []byte) error {
	s, err := smgr.store.New(r, smgr.cookieName)
	if err != nil {
		return fmt.Errorf("could not get new session from session manager: %v", err)
	}
	s.Values[k] = v
	return s.Save(r, w)
}

// staticSessionMgr is a SessionMgr that always returns the same preset session
// value bytes, allowing tests to control the credentials the session bypass sees.
type staticSessionMgr struct {
	b []byte
}

func (smgr staticSessionMgr) Get(r *http.Request, k string) ([]byte, error) {
	return smgr.b, nil
}

func (smgr staticSessionMgr) New(w http.ResponseWriter, r *http.Request, k string, v []byte) error {
	return nil
}

func httpServerWithSessionManager(sm service.SessionMgr) *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.LstdFlags)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(SPNEGOKRB5Authenticate(th, kt, service.Logger(l), service.SessionManager(sm)))
	return s
}

// sessionCredsBytes returns marshaled session credentials as they would have been
// stored in the session after a successful authentication.
func sessionCredsBytes(t *testing.T, validUntil time.Time) []byte {
	t.Helper()
	c := credentials.New("testuser1", "TEST.GOKRB5")
	c.SetAuthenticated(true)
	c.SetAuthTime(time.Now().UTC().Add(-1 * time.Hour))
	c.SetValidUntil(validUntil)
	b, err := c.Marshal()
	if err != nil {
		t.Fatalf("error marshaling session credentials: %v", err)
	}
	return b
}

// rawKRB5TokenAuthHeader builds a raw KRB5 GSS-API token (AP_REQ) around a ticket
// with the given end time and returns it as an Authorization header value.
func rawKRB5TokenAuthHeader(t *testing.T, tktEnd time.Time) string {
	t.Helper()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		tktEnd,
		tktEnd.Add(time.Duration(24)*time.Hour),
	)
	if err != nil {
		t.Fatalf("error getting test ticket: %v", err)
	}
	k5t, err := NewKRB5TokenAPREQ(cl, tkt, sessionKey, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
	if err != nil {
		t.Fatalf("error getting test KRB5 token: %v", err)
	}
	tb, err := k5t.Marshal()
	if err != nil {
		t.Fatalf("error marshaling test KRB5 token: %v", err)
	}
	return "Negotiate " + base64.StdEncoding.EncodeToString(tb)
}

// TestService_SPNEGOKRB_ExpiredSessionCredentials verifies that a request carrying
// a session whose credentials have expired is no longer served under the
// authenticated identity. Without an Authorization header the client must be
// challenged with a 401; with a valid ticket the request must fall through to the
// direct authentication path and be re-authenticated.
func TestService_SPNEGOKRB_ExpiredSessionCredentials(t *testing.T) {
	sm := staticSessionMgr{b: sessionCredsBytes(t, time.Now().UTC().Add(-1*time.Hour))}
	s := httpServerWithSessionManager(sm)
	defer s.Close()

	// Expired session credentials and no Authorization header: must be rejected
	// with a 401 Negotiate challenge, not served under the expired identity.
	r, _ := http.NewRequest("GET", s.URL, nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Request with expired session credentials must not be served under the session identity")
	assert.Equal(t, "Negotiate", httpResp.Header.Get("WWW-Authenticate"), "Negotiation header not set by server.")
	body, _ := io.ReadAll(httpResp.Body)
	httpResp.Body.Close()
	assert.NotContains(t, string(body), "Authenticed user:", "Expired session credentials must not reach the inner handler")

	// Expired session credentials but a valid ticket presented: the request falls
	// through to the direct authentication path and is re-authenticated.
	r2, _ := http.NewRequest("GET", s.URL, nil)
	r2.Header.Set(HTTPHeaderAuthRequest, rawKRB5TokenAuthHeader(t, time.Now().UTC().Add(time.Duration(8)*time.Hour)))
	httpResp2, err := http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	defer httpResp2.Body.Close()
	assert.Equal(t, http.StatusOK, httpResp2.StatusCode, "Request with expired session credentials but a valid ticket should re-authenticate via the direct path")
}

// TestService_SPNEGOKRB_ValidSessionBypass verifies the session bypass keeps
// working when the session credentials have not expired: requests are served
// under the session identity without an Authorization header. A zero ValidUntil
// is treated as no expiry for backward compatibility with sessions written
// before the validity period was recorded.
func TestService_SPNEGOKRB_ValidSessionBypass(t *testing.T) {
	tests := []struct {
		name       string
		validUntil time.Time
	}{
		{name: "ValidUntilInFuture", validUntil: time.Now().UTC().Add(1 * time.Hour)},
		{name: "ValidUntilZero", validUntil: time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := staticSessionMgr{b: sessionCredsBytes(t, tt.validUntil)}
			s := httpServerWithSessionManager(sm)
			defer s.Close()

			r, _ := http.NewRequest("GET", s.URL, nil)
			httpResp, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatalf("Request error: %v\n", err)
			}
			defer httpResp.Body.Close()
			assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Request with valid session credentials should be served under the session identity")
			body, _ := io.ReadAll(httpResp.Body)
			assert.Contains(t, string(body), "Authenticed user: testuser1", "Response should be served under the session identity")
		})
	}
}

// TestService_SPNEGOKRB_ExpiredTicketDirect verifies the direct authentication
// path rejects an expired ticket with a 401, symmetric with the rejection of
// expired session credentials on the session bypass path.
func TestService_SPNEGOKRB_ExpiredTicketDirect(t *testing.T) {
	s := httpServer()
	defer s.Close()

	r, _ := http.NewRequest("GET", s.URL, nil)
	r.Header.Set(HTTPHeaderAuthRequest, rawKRB5TokenAuthHeader(t, time.Now().UTC().Add(-30*time.Minute)))
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	defer httpResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Direct path must reject an expired ticket with a 401")
	assert.Equal(t, spnegoNegTokenRespReject, httpResp.Header.Get("WWW-Authenticate"), "Reject negotiation header not set by server.")
}
