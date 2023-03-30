import { Context } from "@snek-at/function";
import { GraphQLError } from "graphql";

import { sq } from "./index.js";

export interface AuthenticationInfo {
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

    const allAccessToken: string[] = [];

    for (const authHeader of authHeaders) {
      // Get the token from the Authorization header
      const token = authHeader.split(" ")[1];

      // If it is not, add it to the list of all access tokens
      allAccessToken.push(token);
    }

    const infos: AuthenticationInfo[] = [];

    for (const accessToken of allAccessToken) {
      const [userToken, errors] = await sq.query((Query) => {
        const decoded = Query.tokenRead({
          token: accessToken,
        });

        return {
          resourceId: decoded.resourceId,
          userId: decoded.sub,
          scope: decoded.scope,
          expiresAt: new Date(decoded.exp).toISOString(),
        };
      });

      if (errors) {
        throw new GraphQLError(errors[0].message, {
          extensions: errors[0].extensions,
        });
      }

      infos.push(userToken);
    }

    return infos;
  }
}
