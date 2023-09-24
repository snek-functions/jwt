
import { proxy, arrayProxy, fnProxy, fnArrayProxy, t } from "snek-query";

export enum LookupTypeInput {
    USER_ID = "USER_ID",
    EMAIL_ID = "EMAIL_ID"
}
export enum OAuthProvider {
    google = "google",
    azure = "azure"
}
export enum ACCESS_REFRESH {
    access = "access",
    refresh = "refresh"
}
export enum OAuthProviderInput {
    google = "google",
    azure = "azure"
}

export type FilterInput_1 = {
    emailId?: t.String;
    emailAddress?: t.String;
};
export type FilterInput = {
    ids?: t.String[];
    isActive?: t.Boolean;
    isAdmin?: t.Boolean;
};
export type ValuesInput = {
    emailAddress: t.String;
    username: t.String;
    password: t.String;
    accountId?: t.String;
    isActive?: t.Boolean;
    isAdmin?: t.Boolean;
    details?: DetailsInput;
};
export type DetailsInput = {
    firstName?: t.String;
    lastName?: t.String;
};
export type ValuesInput_1 = {
    username?: t.String;
    password?: t.String;
    isActive?: t.Boolean;
    isAdmin?: t.Boolean;
    details?: DetailsInput_1;
};
export type DetailsInput_1 = {
    firstName?: t.String;
    lastName?: t.String;
    avatarFile?: t.String;
};
export type EmailConfigCreateInput = {
    externalCredentialId: t.String;
    isEnabled?: t.Boolean;
};
export type RedirectURLInput = {
    success?: t.String;
    failure?: t.String;
};
export type RedirectURLInput_1 = {
    success?: t.String;
    failure?: t.String;
};
export type ValuesInput_1_2 = {
    emailAddress?: t.String;
    isPrimary?: t.Boolean;
    config?: EmailConfigUpdateInput;
};
export type EmailConfigUpdateInput = {
    externalCredentialId?: t.String;
    isEnabled?: t.Boolean;
};
export type SMTPCredentialInput = {
    host: t.String;
    port: t.Number;
    username: t.String;
    password: t.String;
    secure: t.Boolean;
};
export type OAuthCredentialInput = {
    provider: OAuthProviderInput;
    accessToken: t.String;
    refreshToken: t.String;
};
export type SecretInput = {
    scopeId: t.String;
    name: t.String;
    value: t.NotSupportedYet;
    expiresAt?: t.String;
};
export type GenericObjectInput = {
    object: t.NotSupportedYet;
    expiresAt?: t.String;
    scopeId?: t.String;
    tag?: t.String;
};

export class Query {
    __typename: t.String;
    user: (args?: {
        id?: t.String;
        resourceId?: t.String;
        login?: t.String;
    }) => User;
    allUser: (args?: {
        resourceId?: t.String;
        filter?: FilterInput;
    }) => User[];
    emailLookup: (args: {
        id: t.String;
        type: LookupTypeInput;
    }) => t.Nullable<EmailLookup>;
    resource: (args: {
        id: t.String;
    }) => Resource;
    allResource: Resource[];
    userTokenVerify: (args: {
        token: t.String;
    }) => UserTokenPayload;
    version: t.String;
    constructor() { this.__typename = ""; this.user = fnProxy(User); this.allUser = fnArrayProxy(User); this.emailLookup = fnProxy(EmailLookup); this.resource = fnProxy(Resource); this.allResource = arrayProxy(Resource); this.userTokenVerify = fnProxy(UserTokenPayload); this.version = ""; }
}
export class User {
    __typename: t.String;
    isActive: t.Boolean;
    id: t.String;
    username: t.String;
    resourceId: t.String;
    accountId: t.String;
    isAdmin: t.Boolean;
    createdAt: t.String;
    primaryEmailAddress: t.String;
    email: (args?: {
        filter?: FilterInput_1;
    }) => Email;
    emails: Email[];
    account: Account;
    resource: Resource;
    tokens: Token[];
    details: t.Nullable<Details>;
    externalCredential: (args: {
        id: t.String;
    }) => ExternalCredential;
    externalCredentials: ExternalCredential[];
    constructor() { this.__typename = ""; this.isActive = false; this.id = ""; this.username = ""; this.resourceId = ""; this.accountId = ""; this.isAdmin = false; this.createdAt = ""; this.primaryEmailAddress = ""; this.email = fnProxy(Email); this.emails = arrayProxy(Email); this.account = proxy(Account); this.resource = proxy(Resource); this.tokens = arrayProxy(Token); this.details = proxy(Details); this.externalCredential = fnProxy(ExternalCredential); this.externalCredentials = arrayProxy(ExternalCredential); }
}
export class Email {
    __typename: t.String;
    id: t.String;
    emailAddress: t.String;
    resourceId: t.String;
    isPrimary: t.Boolean;
    isVerified: t.Boolean;
    userId: t.Nullable<t.String>;
    config: t.Nullable<EmailConfig>;
    constructor() { this.__typename = ""; this.id = ""; this.emailAddress = ""; this.resourceId = ""; this.isPrimary = false; this.isVerified = false; this.userId = null; this.config = proxy(EmailConfig); }
}
export class EmailConfig {
    __typename: t.String;
    id: t.String;
    isEnabled: t.Boolean;
    externalCredential: ExternalCredential;
    constructor() { this.__typename = ""; this.id = ""; this.isEnabled = false; this.externalCredential = proxy(ExternalCredential); }
}
export class ExternalCredential {
    __typename: t.String;
    id: t.String;
    smtp: t.Nullable<SMTPCredential>;
    oauth: t.Nullable<OAuthCredential>;
    constructor() { this.__typename = ""; this.id = ""; this.smtp = proxy(SMTPCredential); this.oauth = proxy(OAuthCredential); }
}
export class SMTPCredential {
    __typename: t.String;
    host: t.String;
    port: t.Number;
    username: t.String;
    password: t.String;
    secure: t.Boolean;
    constructor() { this.__typename = ""; this.host = ""; this.port = null; this.username = ""; this.password = ""; this.secure = false; }
}
export class OAuthCredential {
    __typename: t.String;
    provider: t.Nullable<OAuthProvider>;
    accessToken: t.String;
    refreshToken: t.String;
    constructor() { this.__typename = ""; this.provider = null; this.accessToken = ""; this.refreshToken = ""; }
}
export class Account {
    __typename: t.String;
    id: t.String;
    users: User[];
    constructor() { this.__typename = ""; this.id = ""; this.users = arrayProxy(User); }
}
export class Resource {
    __typename: t.String;
    id: t.String;
    name: t.String;
    users: User[];
    config: GenericObject;
    secrets: SecretObject[];
    secret: (args: {
        name: t.String;
    }) => SecretObject;
    constructor() { this.__typename = ""; this.id = ""; this.name = ""; this.users = arrayProxy(User); this.config = proxy(GenericObject); this.secrets = arrayProxy(SecretObject); this.secret = fnProxy(SecretObject); }
}
export class GenericObject {
    __typename: t.String;
    id: t.String;
    value: t.NotSupportedYet;
    tag: t.Nullable<t.String>;
    expiresAt: t.Nullable<t.String>;
    constructor() { this.__typename = ""; this.id = ""; this.value = null; this.tag = null; this.expiresAt = null; }
}
export class SecretObject {
    __typename: t.String;
    name: t.String;
    value: t.NotSupportedYet;
    expiresAt: t.Nullable<t.String>;
    constructor() { this.__typename = ""; this.name = ""; this.value = null; this.expiresAt = null; }
}
export class Token {
    __typename: t.String;
    id: t.String;
    name: t.String;
    expiresAt: t.Nullable<t.String>;
    constructor() { this.__typename = ""; this.id = ""; this.name = ""; this.expiresAt = null; }
}
export class Details {
    __typename: t.String;
    firstName: t.Nullable<t.String>;
    lastName: t.Nullable<t.String>;
    avatarURL: t.Nullable<t.String>;
    constructor() { this.__typename = ""; this.firstName = null; this.lastName = null; this.avatarURL = null; }
}
export class EmailLookup {
    __typename: t.String;
    id: t.String;
    emailAddress: t.String;
    isPrimary: t.Boolean;
    userId: t.Nullable<t.String>;
    constructor() { this.__typename = ""; this.id = ""; this.emailAddress = ""; this.isPrimary = false; this.userId = null; }
}
export class UserTokenPayload {
    __typename: t.String;
    type: t.Nullable<ACCESS_REFRESH>;
    sub: t.String;
    scope: t.NotSupportedYet;
    roles: t.String[];
    iat: t.NotSupportedYet;
    exp: t.NotSupportedYet;
    jti: t.String;
    aud: t.String;
    constructor() { this.__typename = ""; this.type = null; this.sub = ""; this.scope = null; this.roles = []; this.iat = null; this.exp = null; this.jti = ""; this.aud = ""; }
}
export class Mutation {
    __typename: t.String;
    resourceCreate: (args: {
        name: t.String;
    }) => Resource;
    userCreate: (args: {
        resourceId: t.String;
        values: ValuesInput;
        skipEmailVerification: t.Boolean;
    }) => UserCreate;
    userUpdate: (args: {
        id: t.String;
        values: ValuesInput_1;
    }) => User;
    userDelete: (args: {
        id: t.String;
    }) => t.Boolean;
    userTokenCreate: (args: {
        userId: t.String;
        name: t.String;
    }) => t.String;
    userTokenDelete: (args: {
        userId: t.String;
        tokenId: t.String;
    }) => t.Boolean;
    userEmailCreate: (args: {
        userId: t.String;
        emailAddress: t.String;
        isPrimary?: t.Boolean;
        config?: EmailConfigCreateInput;
        redirectURL?: RedirectURLInput;
    }) => Email;
    userEmailConfirm: (args: {
        emailId: t.String;
        otp: t.String;
    }) => Email;
    userEmailConfirmationResend: (args: {
        userId: t.String;
        emailId: t.String;
        redirectURL?: RedirectURLInput_1;
    }) => Email;
    userEmailDelete: (args: {
        userId: t.String;
        emailId: t.String;
    }) => t.Boolean;
    userEmailUpdate: (args: {
        userId: t.String;
        emailId: t.String;
        values: ValuesInput_1_2;
    }) => Email;
    userExternalCredentialCreate: (args: {
        userId: t.String;
        smtp?: SMTPCredentialInput;
        oauth?: OAuthCredentialInput;
    }) => ExternalCredential;
    secretCreate: (args: {
        secret: SecretInput;
    }) => SecretObject;
    genericObjectCreate: (args: {
        genericObject: GenericObjectInput;
    }) => GenericObject;
    deployAuthentication: (args?: {
        resourceId?: t.String;
    }) => Deploy[];
    passwordReset: (args: {
        emailAddress: t.String;
        resourceId: t.String;
    }) => t.String;
    passwordResetConfirm: (args: {
        emailAddress: t.String;
        resourceId: t.String;
        password: t.String;
        otp: t.String;
    }) => t.String;
    constructor() { this.__typename = ""; this.resourceCreate = fnProxy(Resource); this.userCreate = fnProxy(UserCreate); this.userUpdate = fnProxy(User); this.userDelete = () => false; this.userTokenCreate = () => ""; this.userTokenDelete = () => false; this.userEmailCreate = fnProxy(Email); this.userEmailConfirm = fnProxy(Email); this.userEmailConfirmationResend = fnProxy(Email); this.userEmailDelete = () => false; this.userEmailUpdate = fnProxy(Email); this.userExternalCredentialCreate = fnProxy(ExternalCredential); this.secretCreate = fnProxy(SecretObject); this.genericObjectCreate = fnProxy(GenericObject); this.deployAuthentication = fnArrayProxy(Deploy); this.passwordReset = () => ""; this.passwordResetConfirm = () => ""; }
}
export class UserCreate {
    __typename: t.String;
    user: User;
    accessToken: t.String;
    constructor() { this.__typename = ""; this.user = proxy(User); this.accessToken = ""; }
}
export class Deploy {
    __typename: t.String;
    login: t.String;
    resourceId: t.String;
    userId: t.String;
    constructor() { this.__typename = ""; this.login = ""; this.resourceId = ""; this.userId = ""; }
}

