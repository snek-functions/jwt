
import { proxy, arrayProxy, fnProxy, fnArrayProxy, t } from "snek-query";

enum ACCESS_REFRESH {
    access = "access",
    refresh = "refresh"
}


export class Query {
    __typename: t.String;
    tokenRead: (args: {
        token: t.String;
    }) => UserTokenPayload;
    version: t.String;
    constructor() { this.__typename = ""; this.tokenRead = fnProxy(UserTokenPayload); this.version = ""; }
}
export class UserTokenPayload {
    __typename: t.String;
    type: t.Nullable<ACCESS_REFRESH>;
    sub: t.String;
    resourceId: t.String;
    scope: t.NotSupportedYet;
    iat: t.Nullable<t.NotSupportedYet>;
    exp: t.Nullable<t.NotSupportedYet>;
    jti: t.Nullable<t.String>;
    constructor() { this.__typename = ""; this.type = null; this.sub = ""; this.resourceId = ""; this.scope = null; this.iat = null; this.exp = null; this.jti = null; }
}
export class Mutation {
    __typename: t.String;
    tokenCreate: (args: {
        userId: t.String;
        resourceId: t.String;
        scope: t.NotSupportedYet;
    }) => TokenPair;
    tokenRefresh: (args: {
        accessToken: t.String;
        refreshToken: t.String;
    }) => TokenPair;
    constructor() { this.__typename = ""; this.tokenCreate = fnProxy(TokenPair); this.tokenRefresh = fnProxy(TokenPair); }
}
export class TokenPair {
    __typename: t.String;
    accessToken: t.String;
    refreshToken: t.String;
    headers: t.NotSupportedYet;
    constructor() { this.__typename = ""; this.accessToken = ""; this.refreshToken = ""; this.headers = null; }
}

