import { GraphQLError, GraphQLErrorExtensions } from "graphql";

export class InvalidTokenError extends GraphQLError {
  extensions: GraphQLErrorExtensions;
  constructor() {
    super("Invalid token");
    this.extensions = {
      statusCode: 401,
      code: "INVALID_TOKEN",
      description: "The token provided is invalid or has expired",
    };
  }
}

export class TokenExpiredError extends GraphQLError {
  extensions: GraphQLErrorExtensions;
  constructor() {
    super("Token expired");
    this.extensions = {
      statusCode: 401,
      code: "TOKEN_EXPIRED",
      description: "The token provided has expired and a new token is required",
    };
  }
}

export class RefreshTokenExpiredError extends GraphQLError {
  extensions: GraphQLErrorExtensions;
  constructor() {
    super("Refresh token expired");
    this.extensions = {
      statusCode: 401,
      code: "REFRESH_TOKEN_EXPIRED",
      description:
        "The refresh token provided has expired and a new token is required",
    };
  }
}
