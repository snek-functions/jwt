import { defineService } from "@snek-at/function";

import { TokenFactory } from "./utils/TokenFactory";

export default defineService({
  Query: {
    tokenRead: (token: string) => {
      const decodedToken = TokenFactory.readToken(token);

      return decodedToken;
    },
  },
  Mutation: {
    tokenCreate: (
      userId: string,
      resourceId: string,
      scope: {
        [key: string]: string[];
      }
    ) => {
      const tokenPair = TokenFactory.createTokenPair(
        {
          userId,
          resourceId,
        },
        scope
      );

      return tokenPair;
    },
    tokenRefresh: (accessToken: string, refreshToken: string) => {
      // make sure the access token is valid
      TokenFactory.readToken(accessToken, {
        ignoreExpiration: true,
      });

      const refreshedTokenPair =
        TokenFactory.createTokenPairFromRefreshToken(refreshToken);

      return refreshedTokenPair;
    },
  },
});
