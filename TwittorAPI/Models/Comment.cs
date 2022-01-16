using System;
using System.Collections.Generic;

#nullable disable

namespace TwittorAPI.Models
{
    public partial class Comment
    {
        public int Id { get; set; }
        public string ReplySection { get; set; }
        public int TwittorId { get; set; }

        public virtual Twittor Twittor { get; set; }
    }
}
