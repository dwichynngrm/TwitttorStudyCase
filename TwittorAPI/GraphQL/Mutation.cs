using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using HotChocolate;
using HotChocolate.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using TwittorAPI.Kafka;
using TwittorAPI.Models;

namespace TwittorAPI.GraphQL
{
    public class Mutation
    {
        [Authorize(Roles = new[] { "Member" })]
        public async Task<TransactionStatus> AddTwittorAsync(
            TwittorInput input,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var twittor = new Twittor
            {
                UserId = input.UserId,
                TweetSection = input.TweetSection,
                Created = DateTime.Now
            };

            var key = "twittor-add-" + DateTime.Now.ToString();
            var val = JObject.FromObject(twittor).ToString(Formatting.None);
            var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "twittor", key, val);
            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

            var ret = new TransactionStatus(result, "");
            if (!result)
                ret = new TransactionStatus(result, "Failed to submit data");


            return await Task.FromResult(ret);
        }

        [Authorize(Roles = new[] { "Member" })]
        public async Task<TransactionStatus> AddCommentAsync(
            CommentSectionInput input,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var comment = new Comment
            {
                TwittorId = input.TwittorId,
                ReplySection = input.ReplySection,
            };

            var key = "comment-add-" + DateTime.Now.ToString();
            var val = JObject.FromObject(comment).ToString(Formatting.None);
            var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "comment", key, val);
            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

            var ret = new TransactionStatus(result, "");
            if (!result)
                ret = new TransactionStatus(result, "Failed to submit data");


            return await Task.FromResult(ret);
        }

        public async Task<TransactionStatus> UserRegisterAsync(
            UserRegister input,
            [Service] TwittorDbContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var user = context.Users.Where(o => o.Username == input.Username).FirstOrDefault();
            if (user != null)
            {
                return new TransactionStatus(false, "username already taken");
            }
            var newUser = new User
            {
                FullName = input.FullName,
                Email = input.Email,
                Username = input.Username,
                Password = BCrypt.Net.BCrypt.HashPassword(input.Password)
            };

            var key = "user-add-" + DateTime.Now.ToString();
            var val = JObject.FromObject(newUser).ToString(Formatting.None);
            var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "user", key, val);
            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

            var ret = new TransactionStatus(result, "");
            if (!result)
                ret = new TransactionStatus(result, "Failed to submit data");


            return await Task.FromResult(ret);
        }

        public async Task<UserToken> LoginAsync(
            UserLogin input,
            [Service] IOptions<TokenSettings> tokenSettings,
            [Service] TwittorDbContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var user = context.Users.Where(o => o.Username == input.Username).FirstOrDefault();
            if (user == null)
            {
                return await Task.FromResult(new UserToken(null, null, "Username or password was invalid"));
            }
            bool valid = BCrypt.Net.BCrypt.Verify(input.Password, user.Password);
            if (valid)
            {
                var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenSettings.Value.Key));
                var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);

                var claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.Name, user.Username));
                var userRoles = context.UserRoles.Where(o => o.UserId == user.Id).ToList();

                foreach (var userRole in userRoles)
                {
                    var role = context.Roles.Where(o => o.Id == userRole.RoleId).FirstOrDefault();
                    if (role != null)
                    {
                        claims.Add(new Claim(ClaimTypes.Role, role.RoleName));
                    }
                }


                var expired = DateTime.Now.AddHours(3);
                var jwtToken = new JwtSecurityToken(
                    issuer: tokenSettings.Value.Issuer,
                    audience: tokenSettings.Value.Audience,
                    expires: expired,
                    claims: claims,
                    signingCredentials: credentials
                );

                var key = "user-login-" + DateTime.Now.ToString();
                var val = JObject.FromObject(new { Message = $"{input.Username} has signed in" }).ToString(Formatting.None);
                await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

                return await Task.FromResult(
                    new UserToken(new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expired.ToString(), null));
            }

            return await Task.FromResult(new UserToken(null, null, Message: "Username or password was invalid"));
        }

        [Authorize(Roles = new[] { "Member", "Admin" })]
        public async Task<TransactionStatus> UpdateProfileAsync(
            EditProfileInput input,
            [Service] TwittorDbContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var profile = context.Users.Where(o => o.Id == input.Id).FirstOrDefault();
            if (profile != null)
            {
                profile.FullName = input.FullName;
                profile.Email = input.Email;
                profile.Username = input.Username;
                profile.Password = BCrypt.Net.BCrypt.HashPassword(input.Password);

                var key = "update-profile-" + DateTime.Now.ToString();
                var val = JObject.FromObject(profile).ToString(Formatting.None);
                var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "editprofile", key, val);
                await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

                var ret = new TransactionStatus(result, "");
                if (!result)
                    ret = new TransactionStatus(result, "Failed to submit data");
                return await Task.FromResult(ret);
            }
            else
            {
                return new TransactionStatus(false, "Profile doesn't exist");
            }
        }

        [Authorize(Roles = new[] { "Member", "Admin" })]
        public async Task<TransactionStatus> ChangePasswordAsync(
            ChangePwdInput input,
            [Service] TwittorDbContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var akun = context.Users.Where(o => o.Username == input.Username).FirstOrDefault();
            if (akun != null)
            {
                akun.Password = BCrypt.Net.BCrypt.HashPassword(input.Password);
                var key = "change-pass-" + DateTime.Now.ToString();
                var val = JObject.FromObject(akun).ToString(Formatting.None);
                var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "changepassword", key, val);
                await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

                var ret = new TransactionStatus(result, "");
                if (!result)
                    ret = new TransactionStatus(result, "Failed to submit data");
                return await Task.FromResult(ret);
            }
            else
            {
                return new TransactionStatus(false, "User doesn't exist");
            }
        }

        [Authorize(Roles = new[] { "Member" })]
        public async Task<TransactionStatus> DeleteTwittorAsync(
            int userId,
            [Service] TwittorDbContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var twets = context.Twittors.Where(o => o.UserId == userId).ToList();
            bool check = false;
            if (twets != null)
            {
                foreach (var twet in twets)
                {
                    var key = "delete-tweet-" + DateTime.Now.ToString();
                    var val = JObject.FromObject(twet).ToString(Formatting.None);
                    var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "deletetweet", key, val);
                    await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);
                    var ret = new TransactionStatus(result, "");
                    check = true;

                }
                if (!check)
                    return new TransactionStatus(false, "Failed to submit data");
                return await Task.FromResult(new TransactionStatus(true, ""));
            }
            else
            {
                return new TransactionStatus(false, "User has not tweeted yet");
            }
        }


        public async Task<TransactionStatus> AddRoleAsync(
            string roleName,
            [Service] TwittorDbContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var role = context.Roles.Where(o => o.RoleName == roleName).FirstOrDefault();
            if (role != null)
            {
                return new TransactionStatus(false, "Role already exist");
            }
            var newRole = new Role
            {
                RoleName = roleName
            };

            var key = "role-add-" + DateTime.Now.ToString();
            var val = JObject.FromObject(newRole).ToString(Formatting.None);
            var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "role", key, val);
            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

            var ret = new TransactionStatus(result, "");
            if (!result)
                ret = new TransactionStatus(result, "Failed to submit data");

            return await Task.FromResult(ret);
        }

        [Authorize(Roles = new[] { "Admin" })]
        public async Task<TransactionStatus> AddRoleToUserAsync(
            UserRoleInput input,
            [Service] TwittorDbContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var userRole = context.UserRoles.Where(o => o.UserId == input.UserId &&
            o.RoleId == input.RoleId).FirstOrDefault();
            if (userRole != null)
            {
                return new TransactionStatus(false, "Role already exist in this user");
            }

            var newUserRole = new UserRole
            {
                UserId = input.UserId,
                RoleId = input.RoleId
            };

            var key = "user-role-add-" + DateTime.Now.ToString();
            var val = JObject.FromObject(newUserRole).ToString(Formatting.None);
            var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "userrole", key, val);
            await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

            var ret = new TransactionStatus(result, "");
            if (!result)
                ret = new TransactionStatus(result, "Failed to submit data");

            return await Task.FromResult(ret);
        }

        [Authorize(Roles = new[] { "Admin" })]
        public async Task<TransactionStatus> ChangeUserRoleAsync(
            UserRoleInput input,
            [Service] TwittorDbContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var userRole = context.UserRoles.Where(o => o.UserId == input.UserId).FirstOrDefault();
            if (userRole != null)
            {
                userRole.RoleId = input.RoleId;
                var key = "change-user-role-" + DateTime.Now.ToString();
                var val = JObject.FromObject(userRole).ToString(Formatting.None);
                var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "changeuserrole", key, val);
                await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);

                var ret = new TransactionStatus(result, "");
                if (!result)
                    ret = new TransactionStatus(result, "Failed to submit data");
                return await Task.FromResult(ret);
            };
            return new TransactionStatus(false, "User doesn't exist");
        }

        [Authorize(Roles = new[] { "Admin" })]
        public async Task<TransactionStatus> LockUserAsync(
            int userId,
            [Service] TwittorDbContext context,
            [Service] IOptions<KafkaSettings> kafkaSettings)
        {
            var userRoles = context.UserRoles.Where(o => o.UserId == userId).ToList();
            bool check = false;
            if (userRoles != null)
            {
                foreach (var userRole in userRoles)
                {
                    var key = "Lock-User-" + DateTime.Now.ToString();
                    var val = JObject.FromObject(userRole).ToString(Formatting.None);
                    var result = await KafkaHelper.SendMessage(kafkaSettings.Value, "lockuser", key, val);
                    await KafkaHelper.SendMessage(kafkaSettings.Value, "logging", key, val);
                    var ret = new TransactionStatus(result, "");
                    check = true;
                };

                if (!check)
                    return new TransactionStatus(false, "Failed to submit data");
                return await Task.FromResult(new TransactionStatus(true, ""));
            }
            else
            {
                return new TransactionStatus(false, "User doesnt have any role yet");
            }
        }
    }
}
