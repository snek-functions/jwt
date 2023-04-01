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

interface UserTokenPayload {
  type: "access" | "refresh";
  sub: string;
  resourceId: string;
  scope: { [key: string]: string[] };
  iat?: number;
  exp?: number;
  jti: string;
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
    ids: {
      userId: string;
      resourceId: string;
    },
    scope: UserTokenPayload["scope"],
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
      sub: ids.userId,
      resourceId: ids.resourceId,
      type,
      scope,
    };

    const token = jwta.sign(payload, this.signingKey, {
      algorithm: "HS256",
      expiresIn: duration,
      issuer: this.ISSUER,
      jwtid: jwtId,
      audience: "",
    });

    return {
      token,
      jwtId,
    };
  }

  private checkUserTokenPayload(payload: UserTokenPayload): void {
    if (!payload.scope || !payload.sub || !payload.resourceId || !payload.jti) {
      throw new InvalidTokenError();
    }
  }

  verifyToken(token: string, options?: VerifyOptions): UserTokenPayload {
    let payload: UserTokenPayload;

    try {
      payload = jwta.verify(
        token,
        this.signingKey,
        options
      ) as UserTokenPayload;
    } catch {
      throw new TokenExpiredError();
    }

    this.checkUserTokenPayload(payload);

    return payload;
  }

  decodeToken(token: string): UserTokenPayload {
    let payload: UserTokenPayload;

    try {
      payload = jwta.decode(token) as UserTokenPayload;
    } catch {
      throw new TokenExpiredError();
    }

    this.checkUserTokenPayload(payload);

    return payload;
  }

  createTokenPair(
    ids: {
      userId: string;
      resourceId: string;
    },
    scope: UserTokenPayload["scope"],
    refreshTokenPayload?: UserTokenPayload
  ): TokenPair {
    if (refreshTokenPayload) {
      if (refreshTokenPayload.sub !== ids.userId) {
        throw new InvalidTokenError();
      }

      const accessToken = this.createToken(
        "access",
        ids,
        scope,
        refreshTokenPayload.jti
      );

      const refreshToken = this.createToken(
        "refresh",
        ids,
        scope,
        accessToken.jwtId
      );

      return new TokenPair(
        accessToken.jwtId,
        accessToken.token,
        refreshToken.token
      );
    } else {
      const accessToken = this.createToken("access", ids, scope);
      const refreshToken = this.createToken(
        "refresh",
        ids,
        scope,
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
    let payload;

    try {
      payload = this.verifyToken(token);
    } catch (e) {
      throw new RefreshTokenExpiredError();
    }

    if (payload.type !== "refresh") {
      throw new InvalidTokenError();
    }

    return this.createTokenPair(
      {
        userId: payload.sub,
        resourceId: payload.resourceId,
      },
      payload.scope,
      payload
    );
  }
}
