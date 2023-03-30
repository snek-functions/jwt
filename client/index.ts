import { makeSnekQuery } from "snek-query";
import { Query, Mutation } from "./schema.generated.js";

export const sq = makeSnekQuery(
  { Query, Mutation },
  {
    apiURL: "https://services.snek.at/jwt/graphql",
  }
);

export * from "./decorators.js";
export { default as AuthenticationContext } from "./AuthenticationContext.js";
