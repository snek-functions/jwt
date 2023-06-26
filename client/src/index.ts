import { makeSnekQuery } from "snek-query";
import { Query, Mutation } from "./schema.generated.js";

const apiURL =
  process.env.NODE_ENV === "production"
    ? "http://jwt:3000/graphql"
    : "https://services.snek.at/jwt/graphql";

export const sq = makeSnekQuery(
  { Query, Mutation },
  {
    apiURL,
  }
);

export * from "./decorators.js";
export * from "./errors.js";
