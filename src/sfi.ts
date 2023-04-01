import { defineService } from "@snek-at/function";

import { TokenFactory, TokenFactoryOptions } from "./utils/TokenFactory";

export default defineService({
  Query: {
    tokenVerify: (token: string, factoryOptions?: TokenFactoryOptions) => {
      const factory = new TokenFactory(factoryOptions);

      const decodedToken = factory.verifyToken(token);

      return decodedToken;
    },
    tokenDecode: (token: string, factoryOptions?: TokenFactoryOptions) => {
      const factory = new TokenFactory(factoryOptions);

      const decodedToken = factory.decodeToken(token);

      return decodedToken;
    },
  },
  Mutation: {
    tokenCreate: (
      userId: string,
      resourceId: string,
      scope: {
        [key: string]: string[];
      },
      factoryOptions?: TokenFactoryOptions
    ) => {
      const factory = new TokenFactory(factoryOptions);

      const tokenPair = factory.createTokenPair(
        {
          userId,
          resourceId,
        },
        scope
      );

      return tokenPair;
    },
    tokenRefresh: (
      accessToken: string,
      refreshToken: string,
      factoryOptions?: TokenFactoryOptions
    ) => {
      const factory = new TokenFactory(factoryOptions);

      // make sure the access token is valid
      factory.verifyToken(accessToken, {
        ignoreExpiration: true,
      });

      const refreshedTokenPair =
        factory.createTokenPairFromRefreshToken(refreshToken);

      return refreshedTokenPair;
    },
  },
});
