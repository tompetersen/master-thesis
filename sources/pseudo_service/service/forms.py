from crispy_forms.bootstrap import FieldWithButtons
from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit, Layout, Fieldset, ButtonHolder, Div


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
        self.helper.layout = Layout(
            FieldWithButtons('pseudonym', Submit('submit', 'Find', css_class='btn-success')),
        )


class ThresholdSetupForm(forms.Form):

    key_params = forms.ChoiceField(
        label='Key parameters',
        help_text='Determines the used key parameters p, q and g.',
        widget=forms.RadioSelect(),
        initial='static_512',
    )

    clients = forms.MultipleChoiceField(
        label='Clients involved',
        help_text='The number of checked clients yields the threshold parameter n.',
        widget=forms.CheckboxSelectMultiple(attrs={'checked' : 'checked'})
    )

    threshold_t = forms.IntegerField(
        required=True,
        min_value=2,
        initial=2,
        label='Required decryption participants',
        help_text='This must be smaller than the number of checked clients. Describes the threshold parameter t.',
    )

    pseudonym_length = forms.IntegerField(
        required=True,
        min_value=8,
        initial=16,
        label='Pseudonym length',
        help_text='The length of generated pseudonyms in bytes.'
    )

    max_pseudonym_usages = forms.IntegerField(
        required=True,
        min_value=1,
        initial=3,
        label='Maximum pseudonym usages',
        help_text='The maximum number of times a pseudonym will be used.'
    )

    pseudonym_update_interval = forms.IntegerField(
        required=True,
        min_value=1,
        initial=3600, # 6 hrs reasonable?
        label='Pseudonym update interval',
        help_text='The maximum time interval a pseudonym is used (in minutes).'
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

        self.helper.layout = Layout(
            Fieldset(
                'Threshold encryption settings',
                'key_params',
                Div(
                    Div(
                        'clients',
                        css_class='col-4',
                    ),
                    Div(
                        'threshold_t',
                        css_class='col-4',
                    ),
                    css_class='row',
                ),
            ),
            Fieldset(
                'Pseudonymization settings',
                Div(
                    Div(
                        'pseudonym_length',
                        css_class='col-4',
                    ),
                    Div(
                        'max_pseudonym_usages',
                        css_class='col-4',
                    ),
                    Div(
                        'pseudonym_update_interval',
                        css_class='col-4',
                    ),
                    css_class='row',
                ),
            ),
            ButtonHolder(
                Submit('submit', 'Perform setup', css_class='btn-success')
            ),
        )
