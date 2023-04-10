
import { proxy, arrayProxy, fnProxy, fnArrayProxy, t } from "snek-query";

enum ACCESS_REFRESH {
    access = "access",
    refresh = "refresh"
}

type TokenFactoryOptionsInput = {
    signingKey?: t.String;
    accessTokenDuration?: t.String;
    refreshTokenDuration?: t.String;
};

export class Query {
    __typename: t.String;
    tokenVerify: (args: {
        token: t.String;
        factoryOptions?: TokenFactoryOptionsInput;
    }) => UserTokenPayload;
    tokenDecode: (args: {
        token: t.String;
        factoryOptions?: TokenFactoryOptionsInput;
    }) => UserTokenPayload;
    version: t.String;
    constructor() { this.__typename = ""; this.tokenVerify = fnProxy(UserTokenPayload); this.tokenDecode = fnProxy(UserTokenPayload); this.version = ""; }
}
export class UserTokenPayload {
    __typename: t.String;
    type: t.Nullable<ACCESS_REFRESH>;
    sub: t.String;
    resourceId: t.String;
    scope: t.NotSupportedYet;
    iat: t.Nullable<t.NotSupportedYet>;
    exp: t.Nullable<t.NotSupportedYet>;
    jti: t.String;
    constructor() { this.__typename = ""; this.type = null; this.sub = ""; this.resourceId = ""; this.scope = null; this.iat = null; this.exp = null; this.jti = ""; }
}
export class Mutation {
    __typename: t.String;
    tokenCreate: (args: {
        userId: t.String;
        resourceId: t.String;
        scope: t.NotSupportedYet;
        factoryOptions?: TokenFactoryOptionsInput;
    }) => TokenPair;
    tokenRefresh: (args: {
        accessToken: t.String;
        refreshToken: t.String;
        factoryOptions?: TokenFactoryOptionsInput;
    }) => TokenPair;
    constructor() { this.__typename = ""; this.tokenCreate = fnProxy(TokenPair); this.tokenRefresh = fnProxy(TokenPair); }
}
export class TokenPair {
    __typename: t.String;
    id: t.String;
    accessToken: t.String;
    refreshToken: t.String;
    headers: t.NotSupportedYet;
    constructor() { this.__typename = ""; this.id = ""; this.accessToken = ""; this.refreshToken = ""; this.headers = null; }
}

