// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;
using Komogentic.Server.Api;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Komogentic.Server.Tests.Api;

/// <summary>Only the refusals meant for a person become a 400 with their sentence; any other ArgumentException is a
/// fault, a 500 without its message.</summary>
public sealed class ApiErrorsTests
{
    private static EndpointFilterInvocationContext Context() => new DefaultEndpointFilterInvocationContext(new DefaultHttpContext());

    [Fact]
    public async Task User_input_is_a_400_with_its_sentence()
    {
        var result = await ApiErrors.Filter(Context(), _ => throw new UserInputException("An API key's name has 1 to 60 characters."));

        var json = Assert.IsType<JsonHttpResult<ApiError>>(result);
        Assert.Equal((400, "An API key's name has 1 to 60 characters."), (json.StatusCode, json.Value!.Error));
    }

    [Fact]
    public async Task Any_other_argument_exception_stays_a_fault()
    {
        await Assert.ThrowsAsync<ArgumentException>(async () => await ApiErrors.Filter(Context(), _ => throw new ArgumentException("an internal detail")));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await ApiErrors.Filter(Context(), _ => throw new ArgumentOutOfRangeException("x")));
    }
}
