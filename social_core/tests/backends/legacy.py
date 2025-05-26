import requests
import responses

from ...utils import parse_qs
from .base import BaseBackendTest


class BaseLegacyTest(BaseBackendTest):
    form = ""
    response_body = ""

    def setUp(self):
        super().setUp()
        self.strategy.set_settings(
            {
                f"SOCIAL_AUTH_{self.name}_FORM_URL": self.strategy.build_absolute_uri(
                    f"/login/{self.backend.name}"
                )
            }
        )

    def extra_settings(self):
        return {f"SOCIAL_AUTH_{self.name}_FORM_URL": f"/login/{self.backend.name}"}

    def do_start(self):
        start_url = self.strategy.build_absolute_uri(self.backend.start().url)
        complete_url = self.complete_url
        assert complete_url, "Subclasses must set the complete_url attribute"

        responses.add(
            responses.GET,
            start_url,
            status=200,
            body=self.form.format(complete_url),
        )
        responses.add(
            responses.POST,
            complete_url,
            status=200,
            body=self.response_body,
            content_type="application/x-www-form-urlencoded",
        )
        response = requests.get(start_url, timeout=1)
        self.assertEqual(response.text, self.form.format(complete_url))
        response = requests.post(
            complete_url, data=parse_qs(self.response_body), timeout=1
        )
        self.strategy.set_request_data(parse_qs(response.text), self.backend)
        return self.backend.complete()
