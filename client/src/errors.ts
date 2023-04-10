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

export class AuthenticationRequiredError extends GraphQLError {
  extensions: GraphQLErrorExtensions;
  constructor() {
    super("Authentication required");
    this.extensions = {
      statusCode: 401,
      code: "AUTHENTICATION_REQUIRED",
      description: "Authentication is required to access this resource",
    };
  }
}

export class UnauthorizedError extends GraphQLError {
  extensions: GraphQLErrorExtensions;
  constructor() {
    super("Unauthorized");
    this.extensions = {
      statusCode: 403,
      code: "UNAUTHORIZED",
      description: "You are not authorized to perform this action",
    };
  }
}

export class ResourceIdNotProvided extends GraphQLError {
  extensions: GraphQLErrorExtensions;
  constructor() {
    super("Resource ID not provided");
    this.extensions = {
      statusCode: 400,
      code: "RESOURCE_ID_NOT_PROVIDED",
      description: "The resource ID was not provided",
    };
  }
}
