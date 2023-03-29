import { Context } from "@snek-at/function/dist/withContext";

import { AuthenticationFailedError } from "./errors.js";

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
  static accessTokenBlacklist: string[] = [];

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

      // Check if the token is in the blacklist
      if (AuthenticationContext.accessTokenBlacklist.includes(token)) {
        // If it is, throw an error
        throw new AuthenticationFailedError();
      }

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
        throw errors;
      }

      infos.push(userToken);
    }

    return infos;
  }
}
