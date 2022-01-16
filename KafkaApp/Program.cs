using System;
using System.Collections.Generic;
using Confluent.Kafka;
using Confluent.Kafka.Admin;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using KafkaApp.Models;

namespace KafkaApp
{
    public class Program
    {
        static async Task<int> Main(string[] args)
        {
            var builder = new ConfigurationBuilder()
                   .AddJsonFile($"appsettings.json", true, true);

            var config = builder.Build();


            var Serverconfig = new ConsumerConfig
            {
                BootstrapServers = config["Settings:KafkaServer"],
                GroupId = "tester",
                AutoOffsetReset = AutoOffsetReset.Earliest
            };
            CancellationTokenSource cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true; // prevent the process from terminating.
                cts.Cancel();
            };
            Console.WriteLine("--------------Twittor dot com--------------");
            using (var consumer = new ConsumerBuilder<string, string>(Serverconfig).Build())
            {
                Console.WriteLine("Connected");
                var topics = new string[] { "user", "role", "userrole", "lockuser", "changeuserrole", "twittor", "comment", "deletetweet", "changepassword", "updateprofile" };
                consumer.Subscribe(topics);

                Console.WriteLine("Waiting messages....");
                try
                {
                    while (true)
                    {
                        var cr = consumer.Consume(cts.Token);
                        Console.WriteLine($"Consumed record with Topic: {cr.Topic} key: {cr.Message.Key} and value: {cr.Message.Value}");

                        using (var dbcontext = new TwittorDbContext())
                        {
                            if (cr.Topic == "user")
                            {
                                User user = JsonConvert.DeserializeObject<User>(cr.Message.Value);
                                dbcontext.Users.Add(user);
                            }
                            if (cr.Topic == "role")
                            {
                                Role role = JsonConvert.DeserializeObject<Role>(cr.Message.Value);
                                dbcontext.Roles.Add(role);
                            }
                            if (cr.Topic == "userrole")
                            {
                                UserRole userrole = JsonConvert.DeserializeObject<UserRole>(cr.Message.Value);
                                dbcontext.UserRoles.Add(userrole);
                            }
                            if (cr.Topic == "lockuser")
                            {
                                UserRole lockuser = JsonConvert.DeserializeObject<UserRole>(cr.Message.Value);
                                dbcontext.UserRoles.Remove(lockuser);
                            }
                            if (cr.Topic == "changeuserrole")
                            {
                                UserRole changeuserrole = JsonConvert.DeserializeObject<UserRole>(cr.Message.Value);
                                dbcontext.UserRoles.Update(changeuserrole);
                            }
                            if (cr.Topic == "twittor")
                            {
                                Twittor twittor = JsonConvert.DeserializeObject<Twittor>(cr.Message.Value);
                                dbcontext.Twittors.Add(twittor);
                            }
                            if (cr.Topic == "comment")
                            {
                                Comment comment = JsonConvert.DeserializeObject<Comment>(cr.Message.Value);
                                dbcontext.Comments.Add(comment);
                            }
                            if (cr.Topic == "deletetweet")
                            {
                                Twittor twittor = JsonConvert.DeserializeObject<Twittor>(cr.Message.Value);
                                dbcontext.Twittors.Remove(twittor);
                            }
                            if (cr.Topic == "changepassword")
                            {
                                User password = JsonConvert.DeserializeObject<User>(cr.Message.Value);
                                dbcontext.Users.Update(password);
                            }
                            if (cr.Topic == "updateprofile")
                            {
                                User profile = JsonConvert.DeserializeObject<User>(cr.Message.Value);
                                dbcontext.Users.Update(profile);
                            }

                            await dbcontext.SaveChangesAsync();
                            Console.WriteLine("Data was saved into database");
                        }
                    }
                }
                catch (OperationCanceledException)
                {

                }
                finally
                {
                    consumer.Close();
                }

            }

            return 1;
        }
    }
}