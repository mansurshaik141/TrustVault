
from django import forms

from .models import Document
from .validators import validate_document_file


class DocumentUploadForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = [
            "title",
            "description",
            "category",
            "uploaded_file",
        ]

    def clean_uploaded_file(self):
        uploaded_file = self.cleaned_data.get("uploaded_file")

        if uploaded_file:
            validate_document_file(uploaded_file)

        return uploaded_file

class DocumentEditForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = [
            "title",
            "description",
            "category",
        ]
