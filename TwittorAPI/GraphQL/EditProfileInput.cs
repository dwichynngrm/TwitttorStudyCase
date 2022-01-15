namespace TwittorAPI.GraphQL
{
    public record EditProfileInput
    (
        int? UserId,
        string FullName,
        string Email,
        string Username,
        string Password
    );
}
