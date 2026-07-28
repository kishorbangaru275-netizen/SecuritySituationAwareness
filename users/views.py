# Create your views here.
import os.path
import pandas as pd
from django.contrib import messages

from .forms import UserRegistrationForm
from .models import UserRegistrationModel, TokenCountModel
from django.conf import settings

from django.shortcuts import render

SECRET_KEY = "ce9941882f6e044f9809bcee90a2992b4d9d9c21235ab7c537ad56517050f26b"
ALGORITHM = "HS256"


# Create your views here.
def UserRegisterActions(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            print('Data is Valid')
            loginId = form.cleaned_data['loginid']
            TokenCountModel.objects.create(loginid=loginId, count=0)
            form.save()
            messages.success(request, 'You have been successfully registered')
            form = UserRegistrationForm()
            return render(request, 'UserRegistrations.html', {'form': form})
        else:
            messages.success(request, 'Email or Mobile Already Existed')
            print("Invalid form")
    else:
        form = UserRegistrationForm()
    return render(request, 'UserRegistrations.html', {'form': form})


def UserLoginCheck(request):
    if request.method == "POST":
        loginid = request.POST.get('loginid')
        pswd = request.POST.get('pswd')
        print("Login ID = ", loginid, ' Password = ', pswd)
        try:
            check = UserRegistrationModel.objects.get(loginid=loginid, password=pswd)
            status = check.status
            print('Status is = ', status)
            if status == "activated":
                request.session['id'] = check.id
                request.session['loggeduser'] = check.name
                request.session['loginid'] = loginid
                request.session['email'] = check.email
                data = {'loginid': loginid}

                print("User id At", check.id, status)
                return render(request, 'users/UserHomePage.html', {})
            else:
                messages.success(request, 'Your Account Not at activated')
                return render(request, 'UserLogin.html')
        except Exception as e:
            print('Exception is ', str(e))
            pass
        messages.success(request, 'Invalid Login id and password')
    return render(request, 'UserLogin.html', {})


def UserHome(request):
    return render(request, 'users/UserHomePage.html', {})


def view_dataset(request):
    path = os.path.join(settings.MEDIA_ROOT, 'sniff_packets.csv')
    df = pd.read_csv(path)
    html_table = df.to_html(classes='table data-table', index=False)
    html_table = html_table.replace('<td>', '<td class="content-cell">', 9)
    return render(request, 'users/view_dataset.html', {'data': html_table})


def detection_rate(request):
    from .utility.packet_detection_rate import run_detection_from_csv
    path = os.path.join(settings.MEDIA_ROOT, 'sniff_packets.csv')
    results = run_detection_from_csv(path)  # adjust path if needed
    if isinstance(results, dict) and 'error' in results:
        return render(request, 'users/detection_results.html', {'error': results['error']})
    return render(request, 'users/detection_results.html', {'results': results})


def live_captures_packets(request):
    from .utility.live_captures import run_live_detection
    detection_results = run_live_detection()
    return render(request, 'users/live_results.html', {'results': detection_results})

def detection_live(request):
    return render(request, 'users/detection_live.html')