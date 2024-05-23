from django.shortcuts import render
from rest_framework import viewsets
from .serializers import Student_serializers,User_Serializers,Login_serializers,UserView_Serializers,changed_password_serializers,forgot_password_serializers
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Student , User,role
from rest_framework.decorators import api_view , authentication_classes , permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.authentication import BasicAuthentication
from .customPermission import Custom_Permission, User_custom_Permission

from rest_framework.permissions import IsAuthenticated

from django.conf import Settings
from django.core.mail import EmailMessage






from .serializers import User_Serializers,Student_serializers ,Reset_PasswordSerializer,Forgot_Password_Serializer


# Create your views here.

class StudentModelViewSet(viewsets.ModelViewSet):
    queryset=Student.objects.all()
    serializer_class=Student_serializers
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]





@api_view()
def userviews(request):
    # role = User.objects.get('role')
    # print (role)
    user = User.objects.get(id=2)

    print(user.role.get(pk=1))
    print(user.__dict__)
    serializer = User_Serializers(user, many=False)
    return Response(serializer.data)

# """{
# "email":"",
# "password":"",
# "role":1
# }"""

from django.contrib.auth import authenticate

@api_view(['POST'])
def User_View(request):
    if request.method=='POST':
        email = request.data.get('email')
        password = request.data.get('password')
        role=request.data.get('role')

        serializer_data=Login_serializers(data=request.data)

        if serializer_data.is_valid():
           

            user = authenticate(email=email, password=password)

            if user is None:
                return Response ({"Message":"Authenticate Faild . Inavald email and password"})

            user_role= user.role.all()
            print (user_role)
            # User_filter = User.objects.filter(email='admin@gmail.com',password='admin123')

            # User_filter = User.objects.filter(email=email,password=password)

            User_filter = user.role.filter(name=role).first()
            print (User_filter)

            if User_filter is None:
                return Response({"Message":"Invalid role "})
            
            refresh=RefreshToken.for_user(user)
            refresh['role'] = role

            access = str(refresh.access_token)
            refresh=str(refresh)
            
            return Response({"access_token": access, "refresh_token": refresh, "Message": "Role authentication successful."})
        # return Response(serializer.errors, status=400)

        else:

            errors = serializer_data.errors
            return Response(errors,status=400)
            


        # return Response({"Message":"Serializers is not valid"})

        # return Response({"Messsage":"User authenticate successfully : "})


@api_view()
def role_view(request):
    queryset=role.objects.all()
    print(queryset)


from .models import Employer, Manager
from .serializers import Emp_Serializers,Manager_Serializers

@api_view(['GET','POST'])
def Employer_view(request):
    if request.method == 'GET':
        Employers=Employer.objects.all()
        serializers_data = Emp_Serializers(Employers,many=True)
        return Response (serializers_data.data)
    

    elif request.method =='POST':

        json = request.data
        serializers_data=Emp_Serializers(data=json)

        if serializers_data.is_valid():
            serializers_data.save()
            return Response ({"message":"Emp added successfully"})

        return Response({"Message":"Invalid data"})


@api_view(['GET','POST'])

@authentication_classes([BasicAuthentication])
# @permission_classes([IsAuthenticated])
@permission_classes([Custom_Permission])

def Manager_view(request):
    if request.method == 'GET':
        Managers= Manager.objects.all()
        serializers = Manager_Serializers(Managers,many=True)
        return Response (serializers.data)
    
    elif request.method == 'POST':
        json = request.data

        serializers= Manager_Serializers(data=json)

        if serializers.is_valid():
            serializers.save()
            return Response({"Message":" Manager Added Successfuy"})
        
        return Response ({"message":"Invalid Data"})



class UserModelViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserView_Serializers
    permission_classes=[User_custom_Permission]
    roles=['teacher','student','test',12]
    
    # permission_classes=['User_custom_Permission()']

@api_view(['POST'])
def changed_password(request):
    current_password = request.data.get('current_password')
    change_password = request.data.get('change_password')
    email = request.data.get('email')
    serialized_data = changed_password_serializers(data=request.data)


    if serialized_data.is_valid():

        user  = authenticate(password=current_password, email=email)

        if user is not None:
            user.set_password(change_password)
            user.save()
            return Response({'Message':'Change Password Successfully'})
        
        return Response({'Message':'Invalid Password '})
 
@api_view(['POST'])
def forgot_password(request):
    # old_Password = request.data.get('old_password')
    new_Password=request.data.get('new_password')
    email=request.data.get('email')
    otp=request.data.get('otp')
    
    serialized_data = forgot_password_serializers(data=request.data)
        # user=User.objects.get(email=email)

    # if serialized_data.is_valid():
        # user = authenticate(password=new_Password, email=email)

from django.utils.crypto import get_random_string
from django.core.cache import cache  
from django.core.mail import send_mail
# from django.core.cache import cache


            
@api_view(['POST'])

def Send_Otp(request):
    serializer=Reset_PasswordSerializer(data= request.data)
     
    if serializer.is_valid():
        email = serializer.validated_data['email']
        otp =get_random_string(length=6, allowed_chars='0123456789')
        cache.set(email,otp,timeout=300)

        email=User.objects.filter(email=email).first()

        if email is not None:


        
            send_mail(
                'Reset your Password',
                f'Your otp for forgot password is {otp}',
                'anasirfan502@gmail.com',
                
                [email],

                fail_silently=False

            )

            return Response({'Message':'OTP sent to your email'},status=status.HTTP_200_OK)
        
        return Response({'Message':'invalid email'},status=status.HTTP_200_OK)

        
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





@api_view(['POST'])

def forgot_Password(request):
    serializer_data=Forgot_Password_Serializer(data=request.data)

    if serializer_data.is_valid():
        email=serializer_data.validated_data['email']
        otp=serializer_data.validated_data['otp']
        new_password=serializer_data.validated_data['new_password']
        # confirm_password=serializer_data.validated_data['confirm_password']

        cached_otp=cache.get(email)

        if cached_otp == otp:
            try:
                user = User.objects.get(email=email)
                print(user)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
            # user=user.object.get(email=email)
            user.set_password(new_password)
            user.save()
            cache.delete(email)
            
            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        
        return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer_data.errors, status=status.HTTP_400_BAD_REQUEST)






        




           


# ------------------------------------ chat gpt -------------------



# from rest_framework import generics
# # from .models import User
# # from .serializers import YourModelSerializer

# class userviews(generics.ListAPIView):
#     queryset = User.objects.all()
#     serializer_class = User_Serializers







# from django.http import JsonResponse
# from .models import Role  # Apne app mein Role model ka import karein

# @api_view()
# def userviews(request):
#     # User ko fetch karein
#     user = User.objects.get(id=2)

#     # User se jude roles ke IDs nikalein
#     user_roles_ids = User.role.values_list('id', flat=True)

#     # User ke roles ke saath jude Role objects ko fetch karein
#     user_roles = role.objects.filter(id__in=user_roles_ids)

#     # Role objects se role names nikal ke rakhein
#     role_names = [role.name for role in user_roles]

#     # JSON response mein role names ko bhejein
#     return Response({"roles": role_names})



# @api_view(['GET', 'POST'])
# def user_detail(request, pk):
#     user = User.objects.get(pk=pk)
#     if request.method == 'GET':
#         serializer = UserSerializer(user)
#     elif request.method == 'POST':
#         serializer = UserSerializer(user, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#     return Response(serializer.data)




# #     # serializer_class=
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from .models import User
# from .serializers import User_Serializers

# @api_view()
# def userviews(request):
#     queryset = User.objects.all()
#     serializer = User_Serializers(queryset, many=False)
#     return Response(serializer.data)




# from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
# from rest_framework_simplejwt.views import TokenObtainPairView

# class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
#     @classmethod
#     def get_token(cls, user):
#         token = super().get_token(user)
        
#         # Add custom claims to token payload
#         token['role'] = user.role.name  # Assuming user has a single role
        
#         return token

# class CustomTokenObtainPairView(TokenObtainPairView):
#     serializer_class = CustomTokenObtainPairSerializer




# ------------------------------------------

# from rest_framework import viewsets, permissions
# from rest_framework.response import Response
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework_simplejwt.tokens import RefreshToken
# from .models import Student, User
# from .serializers import StudentSerializer, UserSerializer

# class StudentViewSet(viewsets.ModelViewSet):
#     queryset = Student.objects.all()
#     serializer_class = StudentSerializer
#     permission_classes = [permissions.IsAuthenticated]

# @api_view(['POST'])
# @permission_classes([permissions.AllowAny])
# def obtain_token(request):
#     email = request.data.get('email')
#     password = request.data.get('password')
#     user = User.objects.filter(email=email).first()
#     if user and user.check_password(password):
#         token = RefreshToken.for_user(user)
#         return Response({'token': str(token.access_token), 'role': user.role.values_list('name', flat=True)})
#     return Response({'error': 'Unauthorized'}, status=401)




# ---------------------------

