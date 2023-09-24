import { Context } from "@snek-at/function";
import { GraphQLError } from "graphql";

import { InvalidTokenError } from "./errors.js";
import { sq as sqIAM } from "./iam/src/index.js";
import { sq } from "./index.js";
import { AuthenticationCache } from "./authentication-cache.js";

export interface AuthenticationInfo {
  jti: string;
  resourceId: string;
  userId: string;
  scope: {
    [key: string]: string[];
  };
  roles?: string[];
  expiresAt: Date;
}

const tokenCache = new AuthenticationCache();

export default class AuthenticationContext {
  constructor(public context: Context) {
    this.context = context;
  }

  async getAllAuthenticationInfo() {
    // Get all Authorization headers from the request
    const authHeaders =
      this.context.req.headers.authorization?.split(", ") || [];

    const infos: AuthenticationInfo[] = [];

    for (const authHeader of authHeaders) {
      // Check if the authHeader is already cached
      const cachedResponse = tokenCache.getCachedResponse(authHeader);
      if (cachedResponse) {
        infos.push(cachedResponse);
        continue; // Skip token verification
      }

      const [prefix, token] = authHeader.split(" ");

      switch (prefix) {
        case "Bearer":
          const [jwtUserToken, jwtErrors] = await sq.query((Query) => {
            const decoded = Query.tokenVerify({
              token,
            });

            return {
              jti: decoded.jti,
              resourceId: decoded.aud,
              userId: decoded.sub,
              scope: decoded.scope,
              roles: decoded.roles,
              expiresAt: new Date(decoded.exp * 1000),
            };
          });

          if (jwtErrors) {
            throw new GraphQLError(jwtErrors[0].message, {
              extensions: jwtErrors[0].extensions,
            });
          }

          infos.push(jwtUserToken);

          break;

        case "Token":
          const [iamUserToken, iamErrors] = await sqIAM.query((Query) => {
            const decoded = Query.userTokenVerify({
              token,
            });

            return {
              jti: decoded.jti,
              resourceId: decoded.aud,
              userId: decoded.sub,
              scope: decoded.scope,
              roles: decoded.roles,
              expiresAt: new Date(decoded.exp * 1000),
            };
          });

          if (iamErrors) {
            throw new GraphQLError(iamErrors[0].message, {
              extensions: iamErrors[0].extensions,
            });
          }

          infos.push(iamUserToken);

          break;
        default:
          throw new InvalidTokenError();
      }

      // Store the token and its response in the cache
      tokenCache.storeResponse(authHeader, infos[infos.length - 1]);
    }

    return infos;
  }
}
