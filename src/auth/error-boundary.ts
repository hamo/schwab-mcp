import { errorPage } from "./pages";
import { FlowError } from "./state";

export async function withAuthorizationErrorBoundary(
  operation: () => Response | Promise<Response>,
): Promise<Response> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof FlowError) return errorPage(error.message);
    console.error(
      "Authorization flow failed",
      error instanceof Error ? error.name : "unknown",
    );
    return errorPage("The authorization request could not be completed.", 500);
  }
}
