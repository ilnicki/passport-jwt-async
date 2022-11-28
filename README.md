# passport-jwt-async

A [Passport](http://passportjs.org/) strategy for authenticating with a
[JSON Web Token](http://jwt.io).

This module lets you authenticate endpoints using a JSON web token. It is
intended to be used to secure RESTful endpoints without sessions.

## Install

    npm install passport-jwt-async

## Usage

### Configure Strategy

The JWT authentication strategy is constructed as follows:

    new JwtStrategy(options, verify)

`options` is an object literal containing options to control how the token is
extracted from the request and verified.

* `secretOrKey` is a string or buffer containing the secret (symmetric) or PEM-encoded public key (asymmetric) for verifying the token's signature.
* `secretOrKeyProvider(request: Request, rawJwtToken: string): Promise<string | Buffer | undefined>` is a function which should return a secret or PEM-encoded public key (asymmetric) for the given key and request combination. Note it is up to the implementer to decode rawJwtToken.
  Owerrides `secretOrKey`.
* `extractToken(request: Request): string | null` Required. Function that accepts a request as the only parameter and returns either the JWT as a string or null. See [Extracting the JWT from the request](#extracting-the-jwt-from-the-request) for more details.
* `verifyJwt({token: string, secretOrKey: string | Buffer, options: T}): Promise<JwtPayload>`: JWT verifying function. Library contains default imlementation using [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken).
* `verifyJwtOptions`: Contains additional options for `verifyJwt` For `jsonWebTokenVerifier` pass here an options object for any other option you can pass the jsonwebtoken verifier. (i.e maxAge)
* `passReqToCallback`: If true the request will be passed to the verify
  callback. i.e. verify(request, jwtPayload, doneCallback).


`verify` is a function with the parameters `verify(jwtPayload, done)`

* `request` is an Express request.
* `jwtPayload` is an object literal containing the decoded JWT payload.
* `done` is a passport error first callback accepting arguments
  done(error, user, info)

An example configuration which reads the JWT from the http
Authorization header with the scheme 'bearer':

```ts
import {
  Strategy as JwtStrategy,
  fromAuthHeaderAsBearerToken,
  jsonWebTokenVerifier,
} from 'passport-jwt-async';

passport.use(
  new JwtStrategy(
    {
      extractToken: fromAuthHeaderAsBearerToken(),
      secretOrKey: 'secret',
      verifyJwt: jsonWebTokenVerifier,
      verifyJwtOptions: {
        issuer: 'accounts.examplesoft.com',
        audience: 'yoursite.net',
      },
    },
    function ({ payload: { sub } }, done) {
      User.findOne({ id: sub }, function (err, user) {
        if (err) {
          return done(err, false);
        }
        if (user) {
          return done(null, user);
        } else {
          return done(null, false);
          // or you could create a new account
        }
      });
    }
  )
);
```

### Extracting the JWT from the request

There are a number of ways the JWT may be included in a request.  In order to remain as flexible as
possible the JWT is parsed from the request by a user-supplied callback passed in as the
`extractToken` parameter.  This callback, from now on referred to as an extractor,
accepts a request object as an argument and returns the encoded JWT string or null.

#### Included extractors

A number of extractor factory functions are provided in passport-jwt.ExtractJwt. These factory
functions return a new extractor configured with the given parameters.

* ```fromHeader(headerName: string)``` creates a new extractor that looks for the JWT in the given http
  header
* ```fromBodyField(fieldName: string)``` creates a new extractor that looks for the JWT in the given body
  field.  You must have a body parser configured in order to use this method.
* ```fromUrlQueryParameter(paramName: string)``` creates a new extractor that looks for the JWT in the given
  URL query parameter.
* ```fromAuthHeaderWithScheme(authScheme: string)``` creates a new extractor that looks for the JWT in the
  authorization header, expecting the scheme to match auth_scheme.
* ```fromAuthHeaderAsBearerToken()``` creates a new extractor that looks for the JWT in the authorization header
  with the scheme 'bearer'
* ```fromExtractors(extractors: TokenExtractor[])``` creates a new extractor using an array of
  extractors provided. Each extractor is attempted in order until one returns a token.

### Writing a custom extractor function

If the supplied extractors don't meet your needs you can easily provide your own callback. For
example, if you are using the cookie-parser middleware and want to extract the JWT in a cookie
you could use the following function as the argument to the extractToken option:

```ts
const cookieExtractor = (req) => {
    const token = null;
    if (req && req.cookies) {
        token = req.cookies['jwt'];
    }
    return token;
};
```

### Authenticate requests

Use `passport.authenticate()` specifying `'jwt'` as the strategy.

```ts
app.post('/profile', passport.authenticate('jwt', { session: false }),
    function(req, res) {
        res.send(req.user.profile);
    }
);
```

### Include the JWT in requests

The method of including a JWT in a request depends entirely on the extractor
function you choose. For example, if you use the `fromAuthHeaderAsBearerToken`
extractor, you would include an `Authorization` header in your request with the
scheme set to `bearer`. e.g.

    Authorization: bearer JSON_WEB_TOKEN_STRING.....

## Tests

    npm install
    npm test

To generate test-coverage reports:

    npm install -g istanbul
    npm run-script testcov
    istanbul report

## License

The [MIT License](http://opensource.org/licenses/MIT)
