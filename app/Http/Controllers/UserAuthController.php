<?PHP
namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Hash;
use Socialite;
use App\User;

class UserAuthController extends Controller
{
    //Facebook登入
    public function facebookSignInProcess()
    {
        $redirect_url = env('FB_REDIRECT');

        return Socialite::driver('facebook')
            ->scopes(['user_friends'])
            ->redirectUrl($redirect_url)
            ->redirect();
    }
    
    //Facebook登入重新導向授權資料處理
    public function facebookSignInCallbackProcess()
    {
        if (request()->error === "access_denied")
        {
            throw new Exception('授權失敗，存取錯誤');
        }
        
        //依照網域產出重新導向連結 (來驗證是否為發出時同一callback)
        $redirect_url = env('FB_REDIRECT');
 
        //取得第三方使用者資料
        $facebookUser = Socialite::driver('facebook')
            ->fields([
                'name',
                'email',
            ])
            ->redirectUrl($redirect_url)->user();
        $facebook_email = $facebookUser->email;
        
        if (is_null($facebook_email))
        {
            throw new Exception('未授權取得使用者 Email');
        }
        
        //取得 Facebook 資料
        $facebook_id = $facebookUser->id;
        $facebook_name = $facebookUser->name;

        //取得使用者資料是否有此Facebook_id資料
        $user = User::where('facebook_id', $facebook_id)->first();

        if (is_null($user))
        {
            //沒有綁定Facebook Id的帳號，透過Email尋找是否有此帳號
            $user = User::where('email', $facebook_email)->first();
            
            if (!is_null($user))
            {
                //有此帳號，綁定Facebook Id
                $user->facebook_id = $facebook_id;
                $user->save();
            }
        }

        if (is_null($user))
        {
            //尚未註冊
            $input = [
                'email' => $facebook_email, //E-mail
                'name' => $facebook_name, //暱稱
                'password' => uniqid(), //隨機產生密碼
                'facebook_id' => $facebook_id, //Facebook ID
            ];
            
            //密碼加密
            $input['password'] = Hash::make($input['password']);
            
            //新增會員資料
            $user = User::create($input);
        }

        session()->put('user_id', $user->id);
        
        return redirect()->intended('/');
    }
}