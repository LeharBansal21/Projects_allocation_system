import { catchAsyncErrors } from "../middlewares/catchAsyncError.js";
import { User } from "../models/userSchema.js";
import ErrorHandler from "../middlewares/error.js";
import { sendToken } from "../utils/jwtToken.js";

// to check that given email is of lnmiit or not ?
function isLnmiitEmail(email) {
  // Regular expression for validating the specific email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const domain = "@lnmiit.ac.in";

  if (!emailRegex.test(email)) {
    return false;
  }
  const lowercasedEmail = email.toLowerCase();
  // Check if the email ends with '@lnmiit.ac.in'
  if (!lowercasedEmail.endsWith(domain)) {
    return false;
  }
  return true;
}

// TO REGISTER FOR BTP  
export const register = catchAsyncErrors(async (req, res, next) => {
  const { name, email, phone, password, role, branch } = req.body;
  if (!name || !email || !phone || !password || !role) {
    return next(new ErrorHandler("Please fill full form!"));
  }
  const isEmail = await User.findOne({ email });
  if (isEmail) {
    return next(new ErrorHandler("Email already registered!"));
  }
  const totalprojects = 0;
  const currprojects = 0;
  if (!isLnmiitEmail(email)) {
    return next(new ErrorHandler("Enter valid Lnmiit email address only"));
  }
  const user = await User.create({
    name,
    email,
    phone,
    password,
    role,
    totalprojects,
    currprojects,
    branch,
  });
  sendToken(user, 201, res, "User Registered!");
});


//TO LOGIN INTO MY BTP ACCOUNT
export const login = catchAsyncErrors(async (req, res, next) => {
  const { email, password, role } = req.body;
  if (!email || !password || !role) {
    return next(new ErrorHandler("Please provide email ,password and role."));
  }
  const user = await User.findOne({ email }); // password is not selected here
  if (!user) {
    return next(new ErrorHandler("Email is not registered.", 400));
  }
  const userWithPassword = await User.findById(user._id).select("+password");

  const isPasswordMatched = await bcrypt.compare(password, userWithPassword.password);
  if (!isPasswordMatched) {
    return next(new ErrorHandler("Incorrect password.", 400));
  }
  if (user.role !== role) {
    return next(
      new ErrorHandler(`User with provided email and ${role} not found!`, 404)
    );
  }
  sendToken(user, 201, res, "User Logged In!");
});

]

//TO LOGOUT FROM MY BTP ACCOUNT
export const logout = catchAsyncErrors(async (req, res, next) => {
  res
    .status(201)
    .cookie("token", "", {
      // http = true means it prevent javascript running in browser to acces it 
      httpOnly: true,
      expires: new Date(Date.now()),
    })
    .json({
      success: true,
      message: "Logged Out Successfully.",
    });
});

export const getUser = catchAsyncErrors((req, res, next) => {
  const user = req.user;

  res.status(200).json({
    success: true,
    user,
  });
});

//HERE PASSWORD IS INCLUDED TO CHECK THE AUTHENTICATION THAT USER HIMSELF IS ACCESSING OTHERWISE ANYBODY WILL ACCESS THE USER DETAILS
export const getUserDetails = catchAsyncErrors(async (req, res, next) => {
  const { email } = req.params;
  const { password } = req.body;

  // Step 1: Find user with password
  const user = await User.findOne({ email }).select("+password");
  if (!user) {
    return next(new ErrorHandler("User not found.", 404));
  }

  // Step 2: Check password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return next(new ErrorHandler("Incorrect password.", 401));
  }

  // Step 3: Remove password before sending
  const { password: _, ...userWithoutPassword } = user.toObject();

  res.status(200).json({
    success: true,
    userdetails: userWithoutPassword,
  });
});

export const getAllFaculties = catchAsyncErrors(async (req, res, next) => {
  const facultydetails = await User.find({ role: "Faculty" });

  res.status(200).json({
    success: true,
    facultydetails,
  });
});
