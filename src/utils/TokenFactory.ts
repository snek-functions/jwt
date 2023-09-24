import jwta, { VerifyOptions } from "jsonwebtoken";
import crypto from "crypto";

import {
  InvalidTokenError,
  RefreshTokenExpiredError,
  TokenExpiredError,
} from "../errors";

interface FactoryToken {
  token: string;
  jwtId: string;
}

export class TokenPair {
  id: string;
  accessToken: string;
  refreshToken: string;

  constructor(id: string, accessToken: string, refreshToken: string) {
    this.id = id;
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }

  headers(): {} {
    return {
      Authorization: `Bearer ${this.accessToken}`,
    };
  }
}

export interface UserTokenPayload {
  type: "access" | "refresh";
  sub: string;
  scope: { [key: string]: string[] };
  roles?: string[];
  iat?: number;
  exp?: number;
  jti: string;
  aud: string;
}

export interface TokenFactoryOptions {
  signingKey?: string;
  accessTokenDuration?: string;
  refreshTokenDuration?: string;
}

export class TokenFactory {
  private readonly ISSUER = process.env.ISSUER || "snek-0";

  private signingKey: string = process.env.SHARED_SECRET || "snek-0";
  private accessTokenDuration: string = "5m";
  private refreshTokenDuration: string = "30d";

  constructor(options?: TokenFactoryOptions) {
    if (options) {
      if (options.signingKey) {
        this.signingKey = options.signingKey;
      }

      if (options.accessTokenDuration) {
        this.accessTokenDuration = options.accessTokenDuration;
      }

      if (options.refreshTokenDuration) {
        this.refreshTokenDuration = options.refreshTokenDuration;
      }
    }
  }

  private createToken(
    type: "access" | "refresh",
    userId: string,
    resourceId: string,

    auth: {
      scope: UserTokenPayload["scope"]; // deprecated in favor of roles
      roles?: UserTokenPayload["roles"];
    },

    jwtId?: string
  ): FactoryToken {
    jwtId = jwtId || crypto.randomUUID();

    let duration: string | undefined = undefined;

    if (type === "access") {
      duration = this.accessTokenDuration;
    } else if (type === "refresh") {
      duration = this.refreshTokenDuration;
    }

    const payload = {
      type,
      scope: auth.scope,
      roles: auth.roles,
    };

    const token = jwta.sign(payload, this.signingKey, {
      subject: userId,
      algorithm: "HS256",
      expiresIn: duration,
      issuer: this.ISSUER,
      jwtid: jwtId,
      audience: resourceId,
    });

    return {
      token,
      jwtId,
    };
  }

  private checkUserTokenPayload(payload: UserTokenPayload): void {
    if (!payload.scope || !payload.sub || !payload.aud || !payload.jti) {
      throw new InvalidTokenError();
    }
  }

  verifyToken(token: string, options?: VerifyOptions): UserTokenPayload {
    let payload: UserTokenPayload & { resourceId?: string };

    try {
      payload = jwta.verify(
        token,
        this.signingKey,
        options
      ) as UserTokenPayload;
    } catch (e) {
      throw new TokenExpiredError();
    }

    // when a resourceId is provided, use it as the audience
    if (payload.resourceId) {
      payload.aud = payload.resourceId;
    }

    this.checkUserTokenPayload(payload);

    return payload;
  }

  decodeToken(token: string): UserTokenPayload {
    let payload: UserTokenPayload & { resourceId?: string };

    try {
      payload = jwta.decode(token) as UserTokenPayload;
    } catch {
      throw new TokenExpiredError();
    }

    // when a resourceId is provided, use it as the audience
    if (payload.resourceId) {
      payload.aud = payload.resourceId;
    }

    this.checkUserTokenPayload(payload);

    return payload;
  }

  createTokenPair(
    userId: string,
    resourceId: string,
    auth: {
      scope: UserTokenPayload["scope"]; // deprecated in favor of roles
      roles?: string[];
    },
    refreshTokenPayload?: UserTokenPayload
  ): TokenPair {
    if (refreshTokenPayload) {
      if (refreshTokenPayload.sub !== userId) {
        throw new InvalidTokenError();
      }

      const accessToken = this.createToken(
        "access",
        userId,
        resourceId,
        auth,
        refreshTokenPayload.jti
      );

      const refreshToken = this.createToken(
        "refresh",
        userId,
        resourceId,
        auth,
        accessToken.jwtId
      );

      return new TokenPair(
        accessToken.jwtId,
        accessToken.token,
        refreshToken.token
      );
    } else {
      const accessToken = this.createToken("access", userId, resourceId, auth);
      const refreshToken = this.createToken(
        "refresh",
        userId,
        resourceId,
        auth,
        accessToken.jwtId
      );

      return new TokenPair(
        accessToken.jwtId,
        accessToken.token,
        refreshToken.token
      );
    }
  }

  createTokenPairFromRefreshToken(token: string): TokenPair {
    let payload: UserTokenPayload;

    try {
      payload = this.verifyToken(token);
    } catch {
      throw new RefreshTokenExpiredError();
    }

    if (payload.type !== "refresh") {
      throw new InvalidTokenError();
    }

    return this.createTokenPair(
      payload.sub,
      payload.aud,
      {
        scope: payload.scope,
        roles: payload.roles,
      },
      payload
    );
  }
}
