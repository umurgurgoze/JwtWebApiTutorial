using System.Security.Claims;

namespace JwtWebApiTutorial.Services.UserService
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        // 14 - HttpContextAccessor kullanarak gerekli bilgileri alıyoruz.AuthControllerda bunu kullanacağız.
        public string GetMyName()
        {
            var result = string.Empty;
            if (_httpContextAccessor.HttpContext != null)
            {
                result = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            };
            return result;
        }
    }
}
