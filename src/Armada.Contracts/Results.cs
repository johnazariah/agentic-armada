namespace Armada.Contracts;

public abstract record Result<TSuccess, TFailure>
{
    private Result()
    {
    }

    public sealed record Success(TSuccess Value) : Result<TSuccess, TFailure>;

    public sealed record Failure(TFailure Error) : Result<TSuccess, TFailure>;

    public bool IsSuccess => this is Success;
}

public sealed record ContractValidationError(string Code, string Message);
