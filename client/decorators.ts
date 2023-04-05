import { Decorator } from "@snek-at/function";

import AuthContext, { AuthenticationInfo } from "./AuthenticationContext.js";
import {
  AuthenticationRequiredError,
  ResourceIdNotProvided,
  UnauthorizedError,
} from "./errors.js";

/**
 * Context for authentication.
 */
interface AuthenticationContext {
  /**
   * The authentication information.
   * If there is no authentication information available, this will be null.
   */
  auth: AuthenticationInfo | null;

  /**
   * The list of available authentication information.
   * If there is no authentication information available, this will be an empty array.
   */
  multiAuth: AuthenticationInfo[];
}

/**
 * A decorator that checks if the user is authenticated on any resource.
 *
 * If the user is authenticated, the decorator adds the authentication information to the `context.multiAuth` array.
 * If the user is not authenticated, the decorator throws an `AuthenticationRequiredError`.
 */
export const requireAnyAuth: Decorator<
  [],
  { multiAuth: AuthenticationInfo[] }
> = async (context) => {
  // Retrieve authentication information from the context
  const authenticationContext = new AuthContext(context);
  const authenticationInfos =
    await authenticationContext.getAllAuthenticationInfo();

  if (authenticationInfos.length > 0) {
    context.multiAuth = context.multiAuth || [];

    for (const info of authenticationInfos) {
      context.multiAuth.push(info);
    }

    return context;
  }

  throw new AuthenticationRequiredError();
};

/**
 * A decorator that checks if the user is authenticated for the given resource.
 *
 * If the user is authenticated, the decorator adds the authentication information to the `context.auth` property.
 * The authentication that matches the `resourceId` parameter is added to the `context.auth` property.
 * If the user is not authenticated or the `resourceId` parameter is not provided, the decorator throws an error.
 * @param resourceId The ID of the resource to check.
 */
export const requireAuthForResource: Decorator<
  [resourceId: string],
  AuthenticationContext
> = async (context, [resourceId]) => {
  // Ensure that the resource ID is provided
  if (!resourceId) {
    throw new ResourceIdNotProvided();
  }

  // Ensure that the user is authenticated
  const ctx = await requireAnyAuth(context, []);

  const auth = ctx.multiAuth.find((info) => info.resourceId === resourceId);

  if (auth) {
    context.auth = auth;
    context.multiAuth = ctx.multiAuth;

    return context;
  }

  // If the user is not authenticated, throw an authentication required error
  throw new AuthenticationRequiredError();
};

/**
 * A decorator that checks if any user is authenticated.
 *
 * If any user is authenticated, the decorator adds the authentication information to the `context.multiAuth` array.
 * The authentication that matches the `userId` parameter is added to the `context.auth` property.
 * If no user is authenticated, the decorator throws an `AuthenticationRequiredError`.
 * @param userId The ID of the user to check.
 */
export const requireUserAuth: Decorator<
  [userId: string],
  AuthenticationContext
> = async (context, [userId]) => {
  const ctx = await requireAnyAuth(context, []);

  const auth = ctx.multiAuth.find((info) => info.userId === userId);

  if (auth) {
    context.auth = auth;
    context.multiAuth = ctx.multiAuth;

    return context;
  }

  throw new AuthenticationRequiredError();
};

/**
 * A decorator that checks if the user is an admin for the given resource.
 *
 * If the user is authenticated and is an admin for the resource, the decorator continues with the decorated function.
 * If the user is not authenticated or is not an admin for the resource, the decorator throws an `UnauthorizedError`.
 * @param resourceId The ID of the resource to check.
 */
export const requireAdminForResource: Decorator<
  [resourceId: string],
  AuthenticationContext
> = async (context, [resourceId]) => {
  // Ensure that login is required
  const ctx = await requireAuthForResource(context, [resourceId]);

  const auth = ctx.auth;

  if (auth) {
    // Check if the user is an admin
    if (auth.scope["admin"]?.includes("*")) {
      // If the user is an admin, continue with the decorated function

      return ctx;
    }
  }

  // If the user is not an admin, throw an unauthorized error
  throw new UnauthorizedError();
};
