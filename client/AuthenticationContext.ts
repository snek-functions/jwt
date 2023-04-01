import { Context } from "@snek-at/function";
import { GraphQLError } from "graphql";

import { InvalidTokenError } from "./errors.js";
import { sq as sqIAM } from "./iam/index.js";
import { sq } from "./index.js";

export interface AuthenticationInfo {
  jti: string;
  resourceId: string;
  userId: string;
  scope: {
    [key: string]: string[];
  };
  expiresAt: string;
}

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
      const [prefix, token] = authHeader.split(" ");

      switch (prefix) {
        case "Bearer":
          const [jwtUserToken, jwtErrors] = await sq.query((Query) => {
            const decoded = Query.tokenVerify({
              token,
            });

            return {
              jti: decoded.jti,
              resourceId: decoded.resourceId,
              userId: decoded.sub,
              scope: decoded.scope,
              expiresAt: new Date(decoded.exp).toISOString(),
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
              resourceId: decoded.resourceId,
              userId: decoded.sub,
              scope: decoded.scope,
              expiresAt: new Date(decoded.exp).toISOString(),
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
    }

    return infos;
  }
}
