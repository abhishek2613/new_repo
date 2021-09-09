from rest_framework.response import Response
from rest_framework.views import APIView
from account.models import User
from django.contrib.auth import authenticate
import uuid
import datetime
from django.core.mail import EmailMessage
from account.models import otp
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken


class Login_view(APIView):
    def post(self, request):
        response = {}
        response['status'] = 500
        response['message'] = 'something went wrong'

        data = request.data
        email = data.get('email')

        try:
            if data.get('email') is None:
                response['message'] = 'Email is not found'
                raise Exception('Email is nort found')

            if data.get('password') is None:
                response['message'] = 'Password is not found'
                raise Exception('Password is not found')

            user_check = User.objects.filter(email=data.get('email')).first()

            if user_check is None:
                response['message'] = 'Invalid  Email not found'
                raise Exception('Invalid Email not found')



            user_obj = authenticate(email=data.get('email'), password=data.get('password'))

            if user_obj:
                otpp = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(datetime.datetime.today()) + email).int)
                otpp = otpp[0:6]
                request.session['otp'] = otpp

                sub = 'Welcome to University App'
                msg = '''Hi there!
                                               Please confirm Your login Account below otp,''' + str(otpp)
                EmailMessage(sub, msg, to=[email]).send()
                response['message'] = 'Please verify your login account with below otp' + ' ' + str(
                    otpp) + ' we have sent on your email' + ' ' + email
                otpm = otp.objects.create(otpvalue=otpp)
                otpm.save()
                response['status'] = 200
                response['message'] = 'Welcome'

            if user_obj is None:
                response['message'] = 'Invalid password'
                raise Exception('Invalid password')

        except Exception as e:
            print(e)

        return Response(response)



loginview = Login_view.as_view()



class Register_view(APIView):
    def post(self, request):
        response = {}
        response['status'] = 500
        response['message'] = 'something went wrong'

        data = request.data
        email = data.get('email')
        sesemail = request.session['email'] = email

        try:
            if data.get('email') is None:
                response['message'] = 'Email is not found'
                raise Exception('Email is not found')

            user_check = User.objects.filter(email=data.get('email')).first()

            if user_check:
                response['message'] = 'Email already taken!!!'
                raise Exception('Invalid Email not found')

            otpp = str(uuid.uuid5(uuid.NAMESPACE_DNS,str(datetime.datetime.today())+email).int)
            otpp = otpp[0:6]
            request.session['otp'] = otpp


            sub = 'Welcome to University App'
            msg = '''Hi there!
                                   Please confirm Your Account below otp,'''+ str(otpp)
            EmailMessage(sub, msg, to=[email]).send()
            response['message'] = 'Please verify your account with below otp'+' '+str(otpp)+' we have sent on your email'+' '+ email
            otpm = otp.objects.create(otpvalue=otpp)
            otpm.save()

            user = User.objects.create(email=sesemail, password=data.get('password'))
            user.set_password(data.get('password'))
            user.save()

            response['message'] = 'user created'




        except Exception as e:
            print(e)

        return Response(response)




register = Register_view.as_view()


class Verifyotp(APIView):

    def post(self, request):
        response = {}
        response['status'] = 500
        response['message'] = 'something went wrong'

        if request.data.get('otp') is None:
            response['message'] = 'otp is not found'
            raise Exception('otp is not found')

        otpp = request.data.get('otpvalue')
        otpobj = otp.objects.filter(otpvalue=otpp)

        if otpobj:
            response['message'] = 'otp verify'
            response['status'] = 200

        if otpobj is None:
            response['message'] = 'invalid otp'
            response['status'] = 500


verify = Verifyotp.as_view()











