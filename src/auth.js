
const msal = require('@azure/msal-node');
const {msalConfig,REDIRECT_URI,POST_LOGOUT_REDIRECT_URI} = require('./authConfig');


const msalInstance = new msal.ConfidentialClientApplication(msalConfig);
const cryptoProvider = new msal.CryptoProvider();

async function redirectToAuthCodeUrl(req, reply, authCodeUrlRequestParams, authCodeRequestParams) {

    // Generate PKCE Codes before starting the authorization flow
    const { verifier, challenge } = await cryptoProvider.generatePkceCodes();

    // Set generated PKCE codes and method as session vars
    req.session.pkceCodes = {
        challengeMethod: 'S256',
        verifier: verifier,
        challenge: challenge,
    };


    req.session.authCodeUrlRequest = {
        redirectUri: REDIRECT_URI,
        responseMode: 'form_post', // recommended for confidential clients
        codeChallenge: req.session.pkceCodes.challenge,
        codeChallengeMethod: req.session.pkceCodes.challengeMethod,
        ...authCodeUrlRequestParams,
    };

    req.session.authCodeRequest = {
        redirectUri: REDIRECT_URI,
        code: "",
        ...authCodeRequestParams,
    };

    // Get url to sign user in and consent to scopes needed for application
    try {
        const authCodeUrlResponse = await msalInstance.getAuthCodeUrl(req.session.authCodeUrlRequest);
        reply.redirect(authCodeUrlResponse);
    } catch (error) {
        console.error(error);
    }
};

module.exports = async (instance, opts, done) => {

    instance.register(require('@fastify/formbody'))

    instance.get('/signin', async (req, reply) => {
        const state = cryptoProvider.base64Encode(
            JSON.stringify({
                csrfToken: req.session.csrfToken,
                redirectTo: '/'
            })
        );

        const authCodeUrlRequestParams = {
            state: state,
            scopes: [],
        };

        const authCodeRequestParams = {
            scopes: [],
        };

        // trigger the first leg of auth code flow
        return redirectToAuthCodeUrl(req, reply, authCodeUrlRequestParams, authCodeRequestParams)
    })

    instance.get('/signout', function (req, res) {
        /**
         * Construct a logout URI and redirect the user to end the
         * session with Azure AD. For more information, visit:
         * https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request
         */
        const logoutUri = `${msalConfig.auth.authority}/oauth2/v2.0/logout?post_logout_redirect_uri=${POST_LOGOUT_REDIRECT_URI}`;
    
        req.session.destroy(() => {
            res.redirect(logoutUri);
        });
    });

    instance.post('/redirect', async (req, reply) => {

        if (req.body.state) {
            const state = JSON.parse(cryptoProvider.base64Decode(req.body.state));

            // check if csrfToken matches
            if (state.csrfToken === req.session.csrfToken) {
                console.log(!req.session.authCodeRequest)
                req.session.authCodeRequest.code = req.body.code; // authZ code
                req.session.authCodeRequest.codeVerifier = req.session.pkceCodes.verifier // PKCE Code Verifier

                try {
                    const tokenResponse = await msalInstance.acquireTokenByCode(req.session.authCodeRequest);
                    req.session.accessToken = tokenResponse.accessToken;

                    req.session.idToken = tokenResponse.idToken;
                    req.session.account = tokenResponse.account;
                    req.session.isAuthenticated = true;
                    reply.redirect(state.redirectTo);
                } catch (error) {
                    console.error(error);
                }
            } else {
                console.error(new Error('csrf token does not match'));
            }
        } else {
            console.error(new Error('state is missing'));
        }
    });

}
