from crispy_forms.bootstrap import FormActions, FieldWithButtons
from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit, Button, Layout, Fieldset, Field


class PseudonymSearchForm(forms.Form):
    pseudonym = forms.CharField(
        required=True,
        label='',
        help_text='Please enter the pseudonym you want to request the owner for.'
    )

    def __init__(self, *args, **kwargs):
        super(PseudonymSearchForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_action = 'request:find_pseudonym'
        self.helper.form_class = 'form-inline'

        self.helper.label_class = 'ml-1'
        self.helper.field_class = 'ml-1'
        # self.helper.add_input(Submit('submit', 'Find'))
        self.helper.layout = Layout(
            FieldWithButtons('pseudonym', Submit('submit', 'Find', css_class='btn-success')),
        )