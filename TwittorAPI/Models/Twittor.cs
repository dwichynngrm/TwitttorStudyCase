using System;
using System.Collections.Generic;

#nullable disable

namespace TwittorAPI.Models
{
    public partial class Twittor
    {
        public Twittor()
        {
            Comments = new HashSet<Comment>();
        }

        public int Id { get; set; }
        public string TweetSection { get; set; }
        public int UserId { get; set; }
        public DateTime Created { get; set; }

        public virtual User User { get; set; }
        public virtual ICollection<Comment> Comments { get; set; }
    }
}
