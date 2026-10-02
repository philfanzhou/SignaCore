using Microsoft.AspNetCore.Antiforgery;
using Microsoft.EntityFrameworkCore;
using ServiceMantle.Installation;
using ServiceMantle.Web.ManagementApi.Setup;

namespace SignaCore.ReferenceBff;

internal static class BffSetupExecutor
{
    internal static async ValueTask<SetupCompletionResult> ExecuteAsync(
        HttpContext http, SetupCode code, CancellationToken token)
    {
        var result = await ExecuteCoreAsync(http, code, token);
        http.RequestServices.GetRequiredService<BffOperationLog>()
            .Record(BffLogOperation.Setup, result.Status, token);
        return result;
    }

    private static async ValueTask<SetupCompletionResult> ExecuteCoreAsync(
        HttpContext http, SetupCode code, CancellationToken token)
    {
        try
        {
            token.ThrowIfCancellationRequested();
            if (http.User.Identity?.IsAuthenticated != true) return SetupCompletionResult.CredentialInvalid();
            try
            {
                // User-neutral, like every antiforgery validation of the sample and the package:
                // the setup form issues its pair on the signed-in page, and the session CSRF
                // boundary upstream already validated this request's pair the same way.
                await BffAntiforgery.ValidateAsync(
                    http, http.RequestServices.GetRequiredService<IAntiforgery>());
            }
            catch (AntiforgeryValidationException)
            {
                token.ThrowIfCancellationRequested();
                return SetupCompletionResult.ValidationFailed();
            }
            token.ThrowIfCancellationRequested();
            return await RunAsync(code,
                () => new BffSetupSession(http.RequestServices.CreateAsyncScope()),
                () => new ValueTask<BffIdentityCheckResult>(http.RequestServices
                    .GetRequiredService<BffIdentityCheckService>().CheckAsync(http, token)),
                () => new ValueTask(BffSession.RevokeAsync(http, token)), token);
        }
        catch
        {
            token.ThrowIfCancellationRequested();
            return SetupCompletionResult.Unavailable();
        }
    }

    internal static async ValueTask<SetupCompletionResult> RunAsync(
        SetupCode code, Func<IBffSetupSession> createSession,
        Func<ValueTask<BffIdentityCheckResult>> checkIdentity, Func<ValueTask> signOut, CancellationToken token)
    {
        var cleanupFailed = false;
        try
        {
            token.ThrowIfCancellationRequested();
            SetupCompletionResult result;
            var session = createSession();
            try { result = await CompleteAsync(session); }
            finally
            {
                try { await session.DisposeAsync(); }
                catch { cleanupFailed = true; throw; }
            }
            token.ThrowIfCancellationRequested();
            return result;
        }
        catch (Exception exception)
        {
            // Observe the original caller after every normal/exceptional boundary, including
            // scope cleanup. Never expose a dependency exception or misclassify its token.
            token.ThrowIfCancellationRequested();
            return !cleanupFailed && exception is DbUpdateConcurrencyException
                ? SetupCompletionResult.Conflict() : SetupCompletionResult.Unavailable();
        }

        async ValueTask<SetupCompletionResult> CompleteAsync(IBffSetupSession session)
        {
            token.ThrowIfCancellationRequested();
            await session.BeginAsync(token);
            token.ThrowIfCancellationRequested();
            var state = await session.FindAsync(token);
            token.ThrowIfCancellationRequested();
            if (state is null) return SetupCompletionResult.Unavailable();
            if (state.IsCompleted) return SetupCompletionResult.Conflict();
            var validation = await session.ValidateAsync(code, token);
            token.ThrowIfCancellationRequested();
            if (!validation.IsValid) return Map(validation.ErrorCode);
            var identity = await checkIdentity();
            token.ThrowIfCancellationRequested();
            if (identity.Status == BffIdentityCheckStatus.SessionInvalid)
            {
                await signOut();
                token.ThrowIfCancellationRequested();
                return SetupCompletionResult.CredentialInvalid();
            }
            if (identity.Status != BffIdentityCheckStatus.Confirmed) return SetupCompletionResult.Unavailable();
            var staged = await session.StageAsync(identity, token);
            token.ThrowIfCancellationRequested();
            if (!staged.Succeeded) return staged.ErrorCode == "bff.slot_occupied"
                ? SetupCompletionResult.Conflict() : SetupCompletionResult.Unavailable();
            var consumed = await session.ConsumeAsync(code, token);
            token.ThrowIfCancellationRequested();
            if (!consumed.IsStaged) return Map(consumed.ErrorCode);
            await session.SaveAsync(token);
            token.ThrowIfCancellationRequested();
            await session.CommitAsync(token);
            token.ThrowIfCancellationRequested();
            return SetupCompletionResult.Committed();
        }
    }

    private static SetupCompletionResult Map(string? error) => error switch
    {
        WellKnownSetupCodeErrorCodes.InstallationCompleted or WellKnownSetupCodeErrorCodes.ConcurrencyConflict
            => SetupCompletionResult.Conflict(),
        WellKnownSetupCodeErrorCodes.Invalid or WellKnownSetupCodeErrorCodes.Expired
            => SetupCompletionResult.CredentialInvalid(),
        _ => SetupCompletionResult.Unavailable()
    };
}
