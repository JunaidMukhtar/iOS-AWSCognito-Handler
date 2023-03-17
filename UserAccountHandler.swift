//
//  UserAccountHandler.swift
//  MuviNow
//
//  Created by Junaid Mukhtar on 30/08/2018.
//  Copyright © 2020 surjX. All rights reserved.
//

import UIKit
import TSMessages
import AWSCognitoIdentityProvider
import AWSCognitoAuth

class UserAccountHandler: NSObject {

    static let shared = UserAccountHandler()
    
    typealias signInCallback = ((Bool)->Void)?
    var signUpCallBack: ((Bool)->Void)?
    var otpVerificationCallback: ((Bool)->Void)?
    var socialSignupCallBack: ((Bool)->Void)?
    var pool: AWSCognitoIdentityUserPool!
    
    var token: String = ""
    var isUserSignedIn = false
    
    func initialiseAWSAuth(migrationEnabled: Bool) {
        
        AWSDDLog.sharedInstance.logLevel = .verbose
        AWSDDLog.add(AWSDDTTYLogger.sharedInstance)
        let serviceConfiguration = AWSServiceConfiguration.init(region: .APSoutheast2, credentialsProvider: nil)
            
        let configuration = AWSCognitoIdentityUserPoolConfiguration(clientId: AppHandler.kAppSettings.object(forKey: kConfigurations.AWS_CLIENT_ID.rawValue) as! String, clientSecret: AppHandler.kAppSettings.object(forKey: kConfigurations.AWS_CLIENT_SECRET.rawValue) as? String, poolId: AppHandler.kAppSettings.object(forKey:kConfigurations.AWS_USER_POOL_ID.rawValue) as! String, shouldProvideCognitoValidationData: true, pinpointAppId: nil, migrationEnabled: migrationEnabled)
        AWSCognitoIdentityUserPool.register(with: serviceConfiguration, userPoolConfiguration: configuration, forKey: "UserPool")
        
        self.pool = AWSCognitoIdentityUserPool(forKey: "UserPool")
        
        if (self.pool.currentUser()?.isSignedIn)! {
            
            self.getUserDetails { (status) in
                
                print("user status:", status)
                
            }
        }
    }
    
    func signInUserWithEmail(_ userName: String, _ passWord: String , _ completeHandler: @escaping ((Bool, String)->Void)) {
        let (status, message) = self.validateFields(.SIGN_IN, userName, passWord)!
        
        if status == true {
            let emailAttr = AWSCognitoIdentityUserAttributeType()
            emailAttr?.name = "email"
            emailAttr?.value = userName
            let mUser = self.pool.getUser(userName)
            
            // Having a user created we can now login with this credentials
            mUser.getSession(userName, password: passWord, validationData: [emailAttr!])
                .continueWith(block: { [weak self] (task) in
                    
                    guard let session = task.result, task.error == nil else {
                        
                        let error = task.error as NSError?
                        let exceptionString = error?.userInfo["message"] as? String
                        if let type = error?.userInfo["__type"] as? String {
                            if type == ExceptionString.UserNotFoundException.rawValue {
                                completeHandler(false, type)
                            }
                            else {
                                completeHandler(false, exceptionString ?? "")
                            }
                            return nil
                        }
                        else {
                            completeHandler(false, exceptionString ?? "")
                        }
                        return nil
                    }
                    
                    if session.idToken == nil {
                        //not confirmed
                        completeHandler(false, "User not Authenticated")
                    }
                    else {
                        self?.isUserSignedIn = true
                        completeHandler(status,"User authentic")
                    }
                    
                    return nil
                })
        }else{
            completeHandler(status,message)
        }
    }
    
    func signUpWithEmail(_ userName: String, _ passWord: String, _ email: String, _ completeHandler: @escaping ((Bool, String)->Void)) {
        
        let (status, message) = self.validateFields(.SIGN_UP, email, passWord)!
        
        if status == true {
            
            var attributes = [AWSCognitoIdentityUserAttributeType]()
            
            let emailAttribute = AWSCognitoIdentityUserAttributeType.init()
            emailAttribute?.name = "email"
            emailAttribute?.value = email
            
//            let emailAttribute = AWSCognitoIdentityUserAttributeType.init()
//            emailAttribute?.name = "phone_number"
//            emailAttribute?.value = phone
            
            attributes.append(emailAttribute!)
            
            self.pool.signUp(email, password: passWord, userAttributes: attributes, validationData: nil).continueWith { (task) -> Any? in
                
                if task.error != nil {
                    
                    let error = task.error as NSError?
                    let exceptionString = error?.userInfo["message"] as? String
                    completeHandler(false, exceptionString!)
                }
                else {
                    
                    let userStatus = task.result?.userConfirmed?.boolValue
                    
                    if userStatus == false {
                        //not confirmed
                        completeHandler(userStatus!, ExceptionString.UserNotConfirmedException.rawValue)
                    }
                    else {
                        completeHandler(status,"SUCCESS")
                    }
//
                    //should show auth screen if user is not confirmed
                }
                
                return nil
            }
        }
        else {
            completeHandler(status, message)
        }
    }
    
    func updateUserProfile(withAttributes attributes: [AWSCognitoIdentityUserAttributeType], completion: @escaping ((Bool, String)->Void)) {
        
        self.pool.currentUser()?.update(attributes).continueWith(block: { (response) -> Any? in
            
            let error = response.error as NSError?
            
            if error != nil {
                let exceptionString = error?.userInfo["message"] as? String
                completion(false, (exceptionString != nil) ? exceptionString! : "")
            }
            else {
                
                completion(true, "Success")
            }
            return nil
        })
    }
    
    func changePassword(oldPassword:String, newPassword:String, completion: @escaping ((Bool, String)->Void)) {
        
        self.pool.currentUser()?.changePassword(oldPassword, proposedPassword: newPassword).continueWith(block: { (response) -> Any? in
            let error = response.error as NSError?
            
            if error != nil {
                
                if var exceptionString = error?.userInfo["message"] as? String{
                    
                    if exceptionString.contains("Member must have length greater than or equal to 6"){
                        
                        exceptionString = "Old Password is not Correct"
                    }
                    completion(false, exceptionString)
                    
                }else{
                    completion(false, "Unkown Error Occured")
                }
            }
            else {
                
                completion(true, "Password updated successfully")
            }
            return nil
        })
    }
    
    func signoutCurrentUser() {
        
        self.isUserSignedIn = false
        self.pool.currentUser()?.forgetDevice()        
        self.pool.currentUser()?.signOutAndClearLastKnownUser()
        UserModel.sharedUser.signout()
    }
    
    func resendConfirmationCode(_ userName: String) {
        
        self.pool.getUser(userName).resendConfirmationCode()
    }
    
    func signupWithFacebook() {
        
        
    }
    
    func forgotPasswordRequest(for email: String, completion: @escaping ((Bool,String,String?)->Void)) {
        
        self.pool.getUser(email).forgotPassword().continueWith { (response) -> Any? in
            
            let error = response.error as NSError?
            
            if error != nil {
                let exceptionString = error?.userInfo["message"] as? String
                let exceptionType = error?.userInfo["__type"] as? String
                completion(false, exceptionString ?? "", exceptionType)
            }
            else {
                
                completion(true, "Success", nil)
            }
            return nil
        }
    }
    
    func confirmForgotPassword(forEmail email: String, withConfirmationCode confirmationCode: String, andPassword password: String, completion: @escaping ((Bool, String)->Void)) {
        
        self.pool.getUser(email).confirmForgotPassword(confirmationCode, password: password).continueWith { (response) -> Any? in
            
            let error = response.error as NSError?
            
            if error != nil {
                let exceptionString = error?.userInfo["message"] as? String
                completion(false, exceptionString!)
            }
            else {
                completion(true, "Success")
            }
            return nil
        }
    }
    
    func getAuthToken(_ completion: @escaping ((String?)->Void)) {
        
        self.pool.currentUser()?.getSession().continueWith { (response) -> Any? in
            
            let error = response.error as NSError?
            
            if error != nil {
                AppHandler.shared.handleSignoutScenario(nil)
                let exceptionString = error?.userInfo["message"] as? String
                completion(exceptionString)
            }
            else{
                
                let session = response.result
                completion(session?.idToken?.tokenString)
            }
            return nil
        }
    }
    
    func confirmUser(_ confirmationCode: String, email: String, completion: @escaping ((Bool, String?)->Void)) {
        
        self.pool.getUser(email).confirmSignUp(confirmationCode).continueWith { (task) -> Any? in
            
            let error = task.error as NSError?
            let exceptionString = error?.userInfo["message"] as? String
            
            if error == nil {
                completion(true, exceptionString)
            }
            else {                
                completion(false, exceptionString)
            }
            return nil
        }
    }
    
    func getUserDetails(_ completion:@escaping ((Bool)->Void)) {
        
        if self.pool.currentUser() == nil {
            completion(false)
            return
        }
        
        self.pool.currentUser()?.getDetails().continueWith(block: { (response) -> Any? in
            
            let error = response.error as NSError?
            
            if error != nil {
                
                completion(false)
            }
            else {
                let response = response.result
                for attribute in (response?.userAttributes)! {
                    
                    print("Attribute: %@ Value: %@", attribute.name!, attribute.value!)
                    print()
                    
                }
                UserModel.sharedUser.updateUserWithAttributes(attributes: (response?.userAttributes)!)
                completion(true)
            }
            return nil
        })
    }
    
    func validateFields(_ type: kFieldsValidationType, _ email: String, _ password: String) -> (Bool, String)? {
        
        if email.isEmpty == true {
            //error
            return (false, "Email cannot be empty")
        }
        
        if Utilities.validateEmail(email) == false {
            return (false, "Email format is incorrect")
        }
        if password.isEmpty == true {
            return (false, "Password cannot be empty")
        }
        
        switch type {
            
        case .SIGN_IN:
            //specific implementation
            break;
        case .SIGN_UP:
            //specific implementation
            
            let (status, message) = Utilities.validatePassword(password)
            if status == false {
                
                return (status, message)
            }
            
            break;
        }
        return (true, "All Good")
    }
}

class UserModel {
    
    var givenName = ""      //given_name
//    var phoneNumber = ""    //phone_number
    var userImage =  ""     //picture
    var familyName = ""     //family_name
    var gender = ""         //gender
    var birthdate = ""      //birthdate
    var email = ""          //email
    
    static let sharedUser = UserModel()
    
    func updateUserWithAttributes(attributes: Array<AWSCognitoIdentityProviderAttributeType>){
        
        for attribute in attributes {
            
            if attribute.name == "sub" {
                UserDefaults.standard.set(attribute.value, forKey: "CognitoUserId")
                UserDefaults.standard.synchronize()
            }            
            
            if attribute.name == "given_name" {
                UserModel.sharedUser.givenName = attribute.value!
            }
//            else if attribute.name == "phone_number" {
//                UserModel.sharedUser.phoneNumber = attribute.value!
//            }
            else if attribute.name == "picture" {
                UserModel.sharedUser.userImage = attribute.value!
            }
            else if attribute.name == "family_name" {
                UserModel.sharedUser.familyName = attribute.value!
            }
            else if attribute.name == "gender" {
                UserModel.sharedUser.gender = attribute.value!
            }
            else if attribute.name == "birthdate" {
                UserModel.sharedUser.birthdate = attribute.value!
            }
            else if attribute.name == "email" {
                UserModel.sharedUser.email = attribute.value!
            }
            else if attribute.name == "identities" {
                
                do {
                    let x = attribute.value!
                    let myNSData = x.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue))!
                    let parsedData = try JSONSerialization.jsonObject(with: myNSData) as! Array<Any>
                    print(parsedData)
                } catch let error as NSError {
                    print(error)
                }


            }
        }
        if UserModel.sharedUser.givenName.isEmpty {
           UserModel.sharedUser.givenName = Utilities.extractNameFromEmail(UserModel.sharedUser.email)
        }
    }
    
    func signout() {
        
        UserModel.sharedUser.givenName = ""
        UserModel.sharedUser.familyName = ""
//        UserModel.sharedUser.phoneNumber = ""
        UserModel.sharedUser.userImage = ""
        UserModel.sharedUser.gender = ""
        UserModel.sharedUser.birthdate = ""
        UserModel.sharedUser.email = ""
        
        DataHandler.shared.myCollections = nil
        DataHandler.shared.myScreenings = nil
        DataHandler.shared.subscribedMovies = nil
        
    }
    
    func updateUserProfileWith(firstName:String, lastName:String, picture:String, genderRetrieved:String, DOB:String, completion: @escaping ((Bool)->Void)) {
        
        UserModel.sharedUser.givenName = firstName
        UserModel.sharedUser.familyName = lastName
//        UserModel.sharedUser.phoneNumber = phone
        UserModel.sharedUser.userImage = picture
        UserModel.sharedUser.gender = genderRetrieved
        UserModel.sharedUser.birthdate = DOB

        UserModel.sharedUser.updateProfile { (status) in
            
            completion(status)
        }
    }
    
    func updateProfile(completion: @escaping ((Bool)->Void)) {
        
        var attributes = [AWSCognitoIdentityUserAttributeType]()
        
        let firstNameAttribute = AWSCognitoIdentityUserAttributeType.init()
        firstNameAttribute?.name = "given_name"
        firstNameAttribute?.value = UserModel.sharedUser.givenName
        attributes.append(firstNameAttribute!)
        
        let lastName = AWSCognitoIdentityUserAttributeType.init()
        lastName?.name = "family_name"
        lastName?.value = UserModel.sharedUser.familyName
        attributes.append(lastName!)
                
        let userImage = AWSCognitoIdentityUserAttributeType.init()
        userImage?.name = "picture"
        userImage?.value = UserModel.sharedUser.userImage
        attributes.append(userImage!)
        
        let gender = AWSCognitoIdentityUserAttributeType.init()
        gender?.name = "gender"
        gender?.value = UserModel.sharedUser.gender
        attributes.append(gender!)
        
        if UserModel.sharedUser.birthdate.count > 9 {
            
            let birthdate = AWSCognitoIdentityUserAttributeType.init()
            birthdate?.name = "birthdate"
            birthdate?.value = UserModel.sharedUser.birthdate
            attributes.append(birthdate!)
        }
        
        
        UserAccountHandler.shared.updateUserProfile(withAttributes: attributes) { (status, message) in
            
            completion(status)
        }
    }
}
