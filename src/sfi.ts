import {
  ServiceError,
  decorator,
  defineService,
  withContext,
} from "@snek-at/function";

import dotenv from "dotenv";

dotenv.config();

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
    tokenCreate: withContext(
      () =>
        (
          userId: string,
          resourceId: string,
          scope: {
            [key: string]: string[];
          },
          roles?: string[],
          factoryOptions?: TokenFactoryOptions
        ) => {
          const factory = new TokenFactory(factoryOptions);

          const tokenPair = factory.createTokenPair(userId, resourceId, {
            scope,
            roles,
          });

          return tokenPair;
        },
      {
        decorators: [
          decorator(async (context, [test]: [test: string]) => {
            if (process.env.PRESHARED_KEY) {
              // Check for pre-shared key to allow token creation
              if (
                context.req.headers.authorization !== process.env.PRESHARED_KEY
              ) {
                throw new ServiceError("Unauthorized", {
                  code: "UNAUTHORIZED",
                  statusCode: 401,
                  message: "You are not authorized to create tokens.",
                });
              }
            }

            return context;
          }) as any,
        ],
      }
    ),
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
