<?php

namespace ApiBundle\Controller;

use ApiBundle\Entity\User;
use ApiBundle\Form\UserType;
use ApiBundle\Form\UserProfileType;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\HttpFoundation\File\Exception\UploadException;

use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\HttpFoundation\File\UploadedFile;

use FOS\UserBundle\Model\UserInterface;
use Symfony\Component\Validator\Constraints as Assert;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\CollectionType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;

/**
 * Controller used to manage user contents in the backend.
 *
 * This UserController is common to both admin and a normal user.
 *
 * @author Amarendra Kumar Sinha <aksinha@nerdapplabs.com>
 */
class UserController extends Controller
{
    /**
     * Lists all User entities.
     *
     * @Route("/admin/user", name="user_index")
     * @Route("/user", name="admin_user_index")
     * @Method("GET")
     */
    public function indexAction()
    {
        // First, check if admin
        if ($this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
            $repository = $this->getDoctrine()->getRepository('ApiBundle:User');
            $query = $repository->createQueryBuilder('p')
                                  ->where('p.enabled = TRUE')
                                  ->getQuery();
            $users = $query->getResult();

            return $this->render('@ApiBundle/Resources/views/admin/user/index.html.twig', ['users' => $users]);
        }

        // Not an Admin, so check if normal user
        if ($this->get('security.authorization_checker')->isGranted('IS_AUTHENTICATED_FULLY')) {
            return $this->redirectToRoute('homepage');
        }

        // None of the above two cases, so throw exception
        throw $this->createAccessDeniedException();
    }

    /**
     * Creates a new User entity.
     *
     * @Route("/admin/usernew", name="admin_user_new")
     * @Route("/user/new", name="user_new")
     * @Method({"GET", "POST"})
     */
    public function newAction(Request $request)
    {
        $confirmationEnabled = $this->container->getParameter('registration_requires_email_confirmation');
        $userManager = $this->container->get('fos_user.user_manager');
        $user = $userManager->createUser();

        // If reached this page as normal user
        if (!$this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
            $user->setRoles(['ROLE_USER']);
        }

        $form = $this->createForm(UserType::class, $user);

        // If reached this page as admin
        if ($this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
            // Role added in admin area
            $form->add('roles', CollectionType::class, array(
                              'entry_type'   => ChoiceType::class,
                              'entry_options'  => array(
                                  'label' => false,
                                  'choices'  => array(
                                      'ROLE_ADMIN' => 'ROLE_ADMIN',
                                      'ROLE_USER' => 'ROLE_USER',
                                      'ROLE_API'  => 'ROLE_API',
                                      ),
                              ),
            ));
        }

        $locale = $request->getLocale();

        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // $file stores the uploaded Image file
            /** @var Symfony\Component\HttpFoundation\File\UploadedFile $file */
            $file = $user->getImage();

            // If a file has been uploaded
            if ( null != $file ) {
                // First validate uploaded image. If errors found, return to same page with flash errors
                $imageErrors = $this->validateImage($file, $locale);

                if (!$imageErrors) {
                  if ($this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
                      return $this->render('@ApiBundle/Resources/views/admin/user/new.html.twig', [
                          'form' => $form->createView(),
                          'attr' =>  array('enctype' => 'multipart/form-data'),
                      ]);
                  } else {
                    return $this->render('@ApiBundle/Resources/views/user/new.html.twig', [
                        'form' => $form->createView(),
                        'attr' =>  array('enctype' => 'multipart/form-data'),
                    ]);
                  }
                }

                // Generate a unique name for the file before saving it
                $fileName = md5(uniqid()).'.'.$file->guessExtension();

                // Move the file to the directory where images are stored
                $file->move($this->getParameter('images_profile_path'), $fileName );

                // Update the 'image' property to store the Image file name
                // instead of its contents
                $user->setImage($fileName);
            }

            $this->setUserData($user, $form);

            $userManager->updateUser($user);

            if ($this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
                $this->logMessageAndFlash(200, 'success', 'User successfully created: ', $this->get('translator')->trans('flash.user_created_successfully'), $request->getLocale() );
                return $this->redirectToRoute('admin_user_index');
            } else {
                // Normal user should get logged in
                $authUser = false;
                if ($confirmationEnabled) {
                    $this->container->get('session')->set('fos_user_send_confirmation_email/email', $user->getEmail());
                    $route = 'fos_user_registration_check_email';
                } else {
                    $authUser = true;
                    $route = 'fos_user_registration_confirmed';
                }

                $this->logMessageAndFlash(200, 'success', 'User successfully created: ', $this->get('translator')->trans('flash.user_created_successfully'), $request->getLocale() );
                $url = $this->container->get('router')->generate($route);
                $response = new RedirectResponse($url);

                if ($authUser) {
                    $this->authenticateUser($user, $response);
                }

                return $response;
          }
        }

        if ($this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
            return $this->render('@ApiBundle/Resources/views/admin/user/new.html.twig', [
                'form' => $form->createView(),
                'attr' =>  array('enctype' => 'multipart/form-data'),
            ]);
        }

        return $this->render('@ApiBundle/Resources/views/user/new.html.twig', [
            'form' => $form->createView(),
            'attr' =>  array('enctype' => 'multipart/form-data'),
        ]);
    }

    /**
     * Finds and displays a User entity.
     *
     * @Route("/admin/user/{id}", name="admin_user_show", requirements={"id": "\d+"})
     * @Route("/user/profile-show/{id}", name="user_profile_show")
     * @Method("GET")
     */
    public function showAction(User $user)
    {
      // If Admin
      if ($this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
          $deleteForm = $this->createDeleteForm($user);

          return $this->render('@ApiBundle/Resources/views/admin/user/show.html.twig', [
              'user' => $user,
              'delete_form' => $deleteForm->createView(),
          ]);
      }

      // Not an Admin, so check if normal user
      if ($this->get('security.authorization_checker')->isGranted('IS_AUTHENTICATED_FULLY')) {
          return $this->render('@ApiBundle/Resources/views/user/show.html.twig', [
              'user' => $user
          ]);
      }

      // None of the above two cases, so throw exception
      throw $this->createAccessDeniedException();
    }

    /**
     * Displays a form to edit an existing User entity.
     *
     * @Route("/admin/user/edit/{id}", requirements={"id": "\d+"}, name="admin_user_edit")
     * @Route("/user/profile-edit/{id}", name="user_profile_edit")
     * @Method({"GET", "POST"})
     */
    public function editAction(User $user, Request $request)
    {
        $entityManager = $this->getDoctrine()->getManager();

        $currentFilename = $user->getImage();
        if ($user->getImage()) {
          $user->setImage(
              new File($this->getParameter('images_profile_path').'/'.$currentFilename)
          );
        }

        $editForm = $this->createForm(UserProfileType::class, $user);
        $deleteForm = $this->createDeleteForm($user);
        $locale = $request->getLocale();

        // If Admin
        if ($this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
          // Role added in admin area
          $editForm->add('roles', CollectionType::class, array(
                            'entry_type'   => ChoiceType::class,
                            'entry_options'  => array(
                                'label' => false,
                                'choices'  => array(
                                    'ROLE_ADMIN' => 'ROLE_ADMIN',
                                    'ROLE_USER' => 'ROLE_USER',
                                    'ROLE_API'  => 'ROLE_API',
                                    ),
                            ),
          ));
        }
        $editForm->handleRequest($request);

        if ($editForm->isSubmitted() && $editForm->isValid()) {
            // $file stores the uploaded Image file
            /** @var Symfony\Component\HttpFoundation\File\UploadedFile $file */
            $file = $user->getImage();

            // If a file has been uploaded
            if ( null != $file ) {
                // First validate uploaded image. If errors found, return to same page with flash errors
                $imageErrors = $this->validateImage($file, $locale);
                if (!$imageErrors) {
                  // If Admin
                  if ($this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
                      return $this->render('@ApiBundle/Resources/views/admin/user/edit.html.twig', [
                          'user' => $user,
                          'current_image' => $currentFilename,
                          'edit_form' => $editForm->createView(),
                          'delete_form' => $deleteForm->createView(),
                          'attr' =>  array('enctype' => 'multipart/form-data'),
                      ]);
                  } else {
                      return $this->render('@ApiBundle/Resources/views/user/edit.html.twig', [
                          'user' => $user,
                          'current_image' => $currentFilename,
                          'edit_form' => $editForm->createView(),
                          'attr' =>  array('enctype' => 'multipart/form-data'),
                      ]);
                  }
                }

                // Generate a unique name for the file before saving it
                $fileName = md5(uniqid()).'.'.$file->guessExtension();

                // Move the file to the directory where images are stored
                $file->move($this->getParameter('images_profile_path'), $fileName );

                // Update the 'image' property to store the Image file name
                // instead of its contents
                $user->setImage($fileName);
            } else {
                $user->setImage($currentFilename);
            }

            $this->setUserProfileData($user, $editForm);

            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->flush();

            $this->logMessageAndFlash(200, 'success', 'User successfully updated: ', $this->get('translator')->trans('flash.user_updated_successfully'), $request->getLocale() );

            // If Admin
            if ($this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
                return $this->redirectToRoute('admin_user_index');
            } else {
              $route = 'user_profile_show';
              $url = $this->container->get('router')->generate($route, array('id' => $user->getId()));
              $response = new RedirectResponse($url);
              return $response;
            }
        }

        if ($this->get('security.authorization_checker')->isGranted('ROLE_ADMIN')) {
            return $this->render('@ApiBundle/Resources/views/admin/user/edit.html.twig', [
                'user' => $user,
                'current_image' => $currentFilename,
                'edit_form' => $editForm->createView(),
                'delete_form' => $deleteForm->createView(),
                'attr' =>  array('enctype' => 'multipart/form-data'),
            ]);
        } else {
            return $this->render('@ApiBundle/Resources/views/user/edit.html.twig', [
                'user' => $user,
                'current_image' => $currentFilename,
                'edit_form' => $editForm->createView(),
                'attr' =>  array('enctype' => 'multipart/form-data'),
            ]);
        }
    }

    /**
     * Deletes a User entity.
     *
     * @Route("/admin/user/delete/{id}", name="admin_user_delete")
     */
    public function deleteAction(Request $request, User $user)
    {
        // Only Admin can access this page
        $this->denyAccessUnlessGranted('ROLE_ADMIN', null, 'Unable to access this page!');

        $adminUser = $this->container->get('security.context')->getToken()->getUser();

        if ($adminUser->getId() == $user->getId() ) {
            // Admin is not allowed to delete his own account
            $this->logMessageAndFlash(200, 'danger', 'Admin is not allowed to delete his own account', $this->get('translator')->trans('flash.admin_deleted_denied1'), $request->getLocale() );
        } else {
            $entityManager = $this->getDoctrine()->getManager();
            $user->setEnabled(false);
            // $user->setUpdatedAt(new \DateTime());
            $entityManager->flush();
            $this->logMessageAndFlash(200, 'success', 'User successfully deleted: ', $this->get('translator')->trans('flash.user_deleted_successfully'), $request->getLocale() );
        }
        return $this->redirectToRoute('admin_user_index');
    }

    /**
     * Authenticate a user with Symfony Security
     *
     * @param \FOS\UserBundle\Model\UserInterface        $user
     * @param \Symfony\Component\HttpFoundation\Response $response
     */
    protected function authenticateUser(UserInterface $user, Response $response)
    {
        try {
            $this->container->get('fos_user.security.login_manager')->loginUser(
                $this->container->getParameter('fos_user.firewall_name'),
                $user,
                $response);
        } catch (AccountStatusException $ex) {
            // We simply do not authenticate users which do not pass the user
            // checker (not enabled, expired, etc.).
            $this->logMessageAndFlash(200, 'warning', 'User Authentication failed: '.$user->getUsername(), $this->get('translator')->trans('flash.user_authentication_failed'), $request->getLocale() );
        }
    }

    /**
     * Creates a form to delete a User entity by id.
     *
     * @param User $user The user object
     *
     * @return \Symfony\Component\Form\Form The form
     */
    private function createDeleteForm(User $user)
    {
        return $this->createFormBuilder()
            ->setAction($this->generateUrl('admin_user_delete', ['id' => $user->getId()]))
            ->setMethod('DELETE')
            ->getForm()
        ;
    }

    private function setUserData(User $user, \Symfony\Component\Form\Form $form)
    {
      $user->setFirstname($form['firstname']->getData());
      $user->setLastname($form['lastname']->getData());
      $user->setDob($form['dob']->getData());
      $user->setEmail($form['email']->getData());
      $user->setUsername($form['username']->getData());
      $user->setPlainPassword($form['plainPassword']->getData());

      // If Roles exist in form as the form is common for both admin and user areas
      // Only admin area is allowed to have roles
      $roles = array_key_exists('roles', $form) ? $form['roles']->getData() : $user->getRoles();
      $user->setRoles($roles);

      $user->setConfirmationToken(null);
      $user->setEnabled(true);
      $user->setLastLogin(new \DateTime());
    }

    private function setUserProfileData(User $user, \Symfony\Component\Form\Form $form)
    {
      $user->setFirstname($form['firstname']->getData());
      $user->setLastname($form['lastname']->getData());
      $user->setDob($form['dob']->getData());
      $user->setEmail($form['email']->getData());
      $user->setUsername($form['username']->getData());

      // If Roles exist in form as the form is common for both admin and user areas
      // Only admin area is allowed to have roles
      $roles = array_key_exists('roles', $form) ? $form['roles']->getData() : $user->getRoles();
      $user->setRoles($roles);
    }

    private function validateImage(UploadedFile $file, $locale)
    {
        $imageConstraint = new Assert\Image();

        // all constraint "options" can be set this way
        $imageConstraint->mimeTypes = ["image/jpeg", "image/jpg", "image/gif", "image/png"];
        $imageConstraint->mimeTypesMessage = 'Please upload a valid Image (jpeg/jpg/gif/png only within 1024k size';
        $imageConstraint->maxSize = 1024*1024;
        $imageConstraint->minWidth = 100;
        $imageConstraint->minHeight = 100;
        $imageConstraint->payload['api_error'] = 'api.show_error_image';

        // use the validator to validate the value
        $errors = $this->get('validator')->validate($file, $imageConstraint );

        if (count($errors)) {
            // this is *not* a valid image
            $errorArray = [];
            foreach ($errors as $error) {
                $constraint = $error->getConstraint();
                $errorItem = array(
                                    "error_description" => $error->getPropertyPath().': '.$error->getMessage().' '.$error->getInvalidValue(),
                                    "show_message" => $this->get('translator')->trans($constraint->payload['api_error'], array(), 'messages', $locale)
                                  );
                array_push($errorArray, $errorItem);
                $this->logMessageAndFlash(400, 'warning', $errorItem['error_description'], $this->get('translator')->trans('flash.image_error').' '.$errorItem['error_description'], $locale );
            }
            return false;
        }

        return true;
    }

    private function logMessageAndFlash($code = 200, $type = 'success', $logMsg = '', $flashMsg = '', $locale = 'en')
    {
        $this->logMessage($code, $type, $logMsg);
        $this->addFlash($type, $flashMsg);
    }

    private function logMessage($code = 200, $type='success', $logMsg = '') {
        $logger = $this->get('logger');

        if($type === 'success'){
           $logger->info($code . ' ' . $logMsg);
        } else if($type === 'warning'){
           $logger->warning($code . ' ' . $logMsg);
        }
        else if($type === 'danger'){
           $logger->error($code . ' ' . $logMsg);
        }
    }
}
