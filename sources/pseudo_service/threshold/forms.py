from django import forms

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit


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
        #self.helper.form_action = 'threshold:centralizedsetup'
        self.helper.label_class = 'font-weight-bold'
        self.helper.add_input(Submit('submit', 'Perform setup', css_class='btn btn-success'))
