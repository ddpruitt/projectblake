namespace ProjectBlake.Models
{
    public class DocusignViewModel
    {
        public DocusignViewModel(string code, string authGrantTokenContent, string userContent, string jwtToken, string jwtPostContent)
        {
            Code = code;
            AuthGrantTokenContent = authGrantTokenContent;
            UserContent = userContent;
            JwtToken = jwtToken;
            JwtPostContent = jwtPostContent;
        }

        public string Code { get; set; }
        public string AuthGrantTokenContent { get; set; }
        public string UserContent { get; set; }
        public string JwtToken { get; set; }
        public string JwtPostContent { get; set; }
    }
}