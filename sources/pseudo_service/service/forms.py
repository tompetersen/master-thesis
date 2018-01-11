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
        self.helper.form_action = 'service:find_pseudonym'
        self.helper.form_class = 'form-inline'

        self.helper.label_class = 'ml-1'
        self.helper.field_class = 'ml-1'
        # self.helper.add_input(Submit('submit', 'Find'))
        self.helper.layout = Layout(
            FieldWithButtons('pseudonym', Submit('submit', 'Find', css_class='btn-success')),
        )


class ThresholdSetupForm(forms.Form):

    key_params = forms.ChoiceField(
        label='Key parameters',
        help_text='Determines the used key parameters p, q and g.',
        widget=forms.RadioSelect,
    )

    clients = forms.MultipleChoiceField(
        label='Clients involved',
        help_text='Number of checked clients yields the threshold parameter n.',
        widget=forms.CheckboxSelectMultiple
    )

    threshold_t = forms.IntegerField(
        required=True,
        min_value=2,
        initial=2,
        label='Required decryption participants',
        help_text='This must be smaller than the number of checked clients. Describes the threshold parameter t.',
    )

    def __init__(self, *args, **kwargs):
        key_params = kwargs.pop('key_params')
        clients = kwargs.pop('clients')

        super(ThresholdSetupForm, self).__init__(*args, **kwargs)

        self.fields['key_params'].choices = key_params
        self.fields['clients'].choices = clients

        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.label_class = 'font-weight-bold'
        self.helper.add_input(Submit('submit', 'Perform setup', css_class='btn btn-success'))
