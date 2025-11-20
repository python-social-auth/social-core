import json

from .oauth import BaseAuthUrlTestMixin, OAuth2Test


class YahooOAuth2Test(OAuth2Test, BaseAuthUrlTestMixin):
    backend_path = "social_core.backends.yahoo.YahooOAuth2"
    user_data_url = "https://api.login.yahoo.com/openid/v1/userinfo"
    expected_username = "j.doe"
    access_token_body = json.dumps(
        {
            "access_token": "UNQO1djO5xpaKm3_KbECBKB5mlFr6tSZTOLrrJCprtT1X1UFljpxiS5iSue8u_n8ah1WbL6sTNw3HPFHicyXDbTs7aSrbIe.rx9n9dzX7xZjx8dyF2Ap1a6J_nw4k56a5mCOuTd.ZFQENgGtHwM0DRFVeDNTAx_WzhqDGPCqhtsNICuuY30soFZGS11FTlUk7Gy0ISjxLRAjIZVtpojnY5p8XuT1qUtAheWqZegJ_7t.AP4o0J4xJ3_oocXeiSKEXaD3AijdBdViKPZI3Ow7yeHK8uX1weNfKoSP6eEpCviyj0YlRMIBSg4cRdGL6EsSggX6B5gzgcA9efDSpcwVhupY0RlUdi.AxJ1nT0frWmrYiwntpu1XP_5mIbOlb4wfrD_ZCRNY2Qby40RBt5iHERSJ89K1o69fw3Jd4C3hF14iJLHcDHmnYJSX651G9MlpGPWT99DRteCdhSm8URbZqfGPG8mZtLpmhfxr1umCoGEgocrfHpITMjOyEwvgmAhgjGKXugvdNTABn0AEQBetIVtJ80Ymbn6IMq_Qh10vyspVsVK69C9yTlwLtZhcvim5Nk_15JHd0GSj0Mj.X.FWTzUK1e3CNQjeJxdQ2Qk9BXDC4_DXW_Ot5LzYy5qRvRKT4gh54n5aBROxFdky0ELt1IgkLTRJ0idUCen87klP.0CLp1QTNXx99N6nM9c_HwWVKwhILUjzXaIrP0GVEMwlGIHqn2I91Z03irBgzrMB219lqUAuF27_OD4QnyQfICSW65n5hVo1e89xwN6VN3usRrhHmdDfd7nk3nzMyXdsOPzghA1huBCYyEGZ_kq9FzVFQ5QYDmJ0WqpmG1yXDEntYVvkB_i_jkbNPH4.R134ptwznCZSuQ--",
            "refresh_token": "AJj.Dlbt_e4XN85buQhFXj77sIB3lqBF3Bcqb2kwUEoYrBb0Pg--",
            "expires_in": 3600,
            "token_type": "bearer",
            "xoauth_yahoo_guid": "UQIDWJNWVNQD4GXZ5NGMZUSTQ4",
            "id_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6IjM0NjZkNTFmN2RkMGM3ODA1NjU2ODhjMTgzOTIxODE2YzQ1ODg5YWQifQ.eyJhdF9oYXNoIjoiYWM5YkR3ejVMWjl5UEVpdWtEcGdzdz09Iiwic3ViIjoiVVFJRFdKTldWTlFENEdYWjVOR01aVVNUUTQiLCJhdWQiOiJkajB5Sm1rOVdHeDBRbEUwVVdkQ2EwaEtKbVE5V1Zkck9XTnJOVWhYVm5CaFRraEZiV05IYnpsTlFTMHRKbk05WTI5dWMzVnRaWEp6WldOeVpYUW1lRDAxT0EtLSIsImlzcyI6Imh0dHBzOi8vbG9naW4ueWFob28uY29tIiwiZXhwIjoxNDQzODI3MTMwLCJub25jZSI6IjEyMzQ1IiwiaWF0IjoxNDQzODIzNTMwfQ.n7oEFi5028StcI41Hkh6lLYK4PmF7pT4AIXrQ_62nfDEZj2g0oYjSLFPJp4IqF6LefwcCQ9FHT5X9eC8A7peqw",
        }
    )
    user_data_body = json.dumps(
        {
            "sub": "FSVIDUW3D7FSVIDUW3D72F2F",  # user identifier
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "preferred_username": "j.doe",
            "email": "janedoe@example.com",
            "picture": "http://example.com/janedoe/me.jpg",
        }
    )

    def test_login(self) -> None:
        self.do_login()

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()
