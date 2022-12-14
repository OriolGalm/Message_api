<?php

namespace App\Controllers\Api;

use CodeIgniter\RESTful\ResourceController;
use App\Models\UserModel;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Exception;
use \App\Validation\CustomRules;
use \CodeIgniter\Files\File;

class UserController extends ResourceController
{

    public function register()
    {
        $rules = [
            "name" => "required",
            "email" => "required|valid_email|is_unique[users.email]|min_length[6]",
            "password" => "required|min_length[6]"
        ];

        $messages = [
            "name" => "Name is required",
            "email" => [
                "required" => "Email required",
                "valid_email" => "Email address is not in format",
                "is_unique" => "This email already exists"
            ],
            "password" => [
                "required" => "password is required",
                "min_length" => "The password must have min 6 characters"
            ]
        ];

        if (!$this->validate($rules, $messages)) {

            $response = [
                'status' => 500,
                'error' => true,
                'message' => $this->validator->getErrors(),
                'data' => []
            ];
        } else {

            $userModel = new UserModel();

            $data = [
                "name" => $this->request->getVar("name"),
                "email" => $this->request->getVar("email"),
                "password" => password_hash($this->request->getVar("password"), PASSWORD_DEFAULT),
            ];

            if ($userModel->insert($data)) {

                $response = [
                    'status' => 200,
                    "error" => false,
                    'messages' => 'Successfully, user has been registered',
                    'data' => []
                ];
            } else {

                $response = [
                    'status' => 500,
                    "error" => true,
                    'messages' => 'Failed to create user',
                    'data' => []
                ];
            }
        }

        return $this->respond($response);
    }

    public function login()
    {
        $rules = [
            "email" => "required|valid_email|min_length[6]",
            "password" => "required",
        ];

        $messages = [
            "email" => [
                "required" => "Email required",
                "valid_email" => "Email not valid"
            ],
            "password" => [
                "required" => "Password is required"
            ],
        ];

        if (!$this->validate($rules, $messages)) {

            $response = [
                'status' => 500,
                'error' => true,
                'messages' => $this->validator->getErrors(),
                'data' => []
            ];
            
        } else {
            $userModel = new UserModel();

            $userdata = $userModel->where("email", $this->request->getVar("email"))->first();

            if (!empty($userdata)) {

                if (password_verify($this->request->getVar("password"), $userdata['password'])) {

                    $key = getenv('JWT_SECRET');

                    $iat = time(); // current timestamp value
                    $nbf = $iat + 10;
                    $exp = $iat + 3600;

                    $payload = array(
                        "iat" => $iat, // issued at
                        "nbf" => $nbf, //not before in seconds
                        "exp" => $exp, // expire time in seconds
                        "data" => array(
                                    'id' => $userdata['id'],
                                    'name' => $userdata['name'],
                                    'email' => $userdata['email'],
                                    'role' => 4,
                                ),
                    );
                   
                   $token = JWT::encode($payload, $key, 'HS256');
                    $response = [
                        'status' => 200,
                        'error' => false,
                        'messages' => 'User logged In successfully',
                        'data' => [
                            'token' => $token
                        ]
                    ];
                } else {

                    $response = [
                        'status' => 500,
                        'error' => true,
                        'messages' => 'Incorrect password',
                        'data' => []
                    ];
                }
            } else {
                $response = [
                    'status' => 500,
                    'error' => true,
                    'messages' => 'User not found',
                    'data' => []
                ];
               
            }
        }
        return $this->respond($response);
    }

    public function updateUser($emp_id)
    {
		/* if(trim($data->isbn) != trim($this->request->getVar('phone'))){
			$this->form_validation->set_rules('isbn', 'isbn', 'required|is_unique[user.phone]');
		} else {
			$this->form_validation->set_rules('isbn', 'isbn', 'required');
		} */
        /* $rules = [
            "email" => "required|valid_email|min_length[6]",
            "password" => "required", 
            "name" => "required"
		];

		$messages = [
			
            "email" => [
                "required" => "Email required",
                "valid_email" => "Email address is not in format"
            ],
            "password" => [
                "required" => "Password is required"
            ], 
            "name" => [
                "required" => "Name is required"
            ],
		];

		if (!$this->validate($rules, $messages)) {

			$response = [
				'status' => 500,
				'error' => true,
				'message' => $this->validator->getErrors(),
				'data' => []
			];
		} else {  */

			$emp = new UserModel();

			if ($emp->find($emp_id)) {

				//Retrieving Raw Data (PUT, PATCH, DELETE)
				$input = $this->request->getRawInput();	
				$data['name'] = $this->request->getVar("name");
				$data['image'] = $this->request->getVar("image");
				$data['message'] = $this->request->getVar("message");
				

				$emp->update($emp_id, $data);

				$response = [
					'status' => 200,
					'error' => false,
					'message' => 'User updated successfully',
					'data' => []
				];
			}else {

				$response = [
					'status' => 500,
					"error" => true,
					'messages' => 'User not found',
					'data' => []
				];
			}
		//}

		return $this->respond($response);
    }

    public function imageUser($user_id)
    {
        helper(['array']);

        $rules = [
            "image" => "uploaded[image]|max_size[image, 1024]|is_image[image]"
        ];

        $messages = [
            "image" => [
                "max_size" => "Image cannot be larger than 1024 Mb",
                "ext_in" => "Not a valid image"
                ]
        ];

        if (!$this->validate($rules, $messages)) {
            
            $response = [
				'status' => 500,
				'error' => true,
				'message' => $this->validator->getErrors(),
				'data' => []
			];

        }else{
            $user = new UserModel();

            $fileName = dot_array_search('image.name', $_FILES);

            $data = [
                'id' => $user_id
            ];

            if($fileName != ''){

                $file = $this->request->getFile('image');
                if(! $file->isValid())
                    return $this->fail($file->getErrorString());

                $file->move('./assets/upload');
                $data['image'] = $file->getName();
            }

            $user->update($user_id, $data);
            //$this->model->save($data);
            return $this->respond($data);
        }
    }

    public function getImage($user_id)
	{
		$user = new UserModel();
        
        $fileName = $user->select('image')->where('id', $user_id)->first();
        $data = base_url('assets/upload/$fileName'); 
        return $data;
	}

    public function details()
    {
        $key = getenv('JWT_SECRET');

        try {
            //$header = $this->request->getHeader("Authorization");
            $token = $this->request->getServer("HTTP_AUTHORIZATION");
            $token = str_replace('Bearer ', '', $token);
            $decoded = JWT::decode($token, new Key($key, 'HS256'));
            if ($decoded) {
                $response = [
                    'status' => 200,
                    'error' => false,
                    'messages' => 'User details',
                    'data' => [
                        'profile' => $decoded->data
                    ]
                ];
            }
        } catch (Exception $ex) {
            $response = [
                'status' => 401,
                'error' => true,
                'messages' => 'Access denied',
                'data' => []
            ];
           
        }
        return $this->respond($response);
    }

    public function deleteUser($user_id)
    {
        $user = new UserModel();

		$data = $user->find($user_id);

		if (!empty($data)) {

			$user->delete($user_id);

			$response = [
				'status' => 200,
				"error" => false,
				'messages' => 'User deleted successfully',
				'data' => []
			];

		} else {

			$response = [
				'status' => 500,
				"error" => true,
				'messages' => 'No user found',
				'data' => []
			];
		}

		return $this->respond($response);
    }

    public function showUser($user_id)
	{
		$user = new UserModel();

		$data = $user->find($user_id);
        //$data = $model->where(['id' => $user_id])->first();

		if (!empty($data)) {

			$response = [
				'status' => 200,
				"error" => false,
				'messages' => 'Single user data',
				'data' => $data
			];

		} else {

			$response = [
				'status' => 500,
				"error" => true,
				'messages' => 'No user found',
				'data' => []
			];
		}

		return $this->respond($response);
	}
}
