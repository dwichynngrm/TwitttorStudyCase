namespace TwittorAPI.GraphQL
{
    public record EditProfileInput
    (
        int? Id,
        string FullName,
        string Email,
        string Username,
        string Password
    );
}
