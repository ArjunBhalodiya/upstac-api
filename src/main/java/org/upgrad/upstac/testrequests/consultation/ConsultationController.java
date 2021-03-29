package org.upgrad.upstac.testrequests.consultation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.upgrad.upstac.config.security.UserLoggedInService;
import org.upgrad.upstac.exception.AppException;
import org.upgrad.upstac.testrequests.RequestStatus;
import org.upgrad.upstac.testrequests.TestRequest;
import org.upgrad.upstac.testrequests.TestRequestQueryService;
import org.upgrad.upstac.testrequests.TestRequestUpdateService;
import org.upgrad.upstac.users.User;

import javax.validation.ConstraintViolationException;
import java.util.List;

import static org.upgrad.upstac.exception.UpgradResponseStatusException.asBadRequest;
import static org.upgrad.upstac.exception.UpgradResponseStatusException.asConstraintViolation;

@RestController
@RequestMapping("/api/consultations")
public class ConsultationController {

  Logger log = LoggerFactory.getLogger(ConsultationController.class);

  @Autowired private TestRequestUpdateService testRequestUpdateService;

  @Autowired private TestRequestQueryService testRequestQueryService;

  @Autowired private UserLoggedInService userLoggedInService;

  @GetMapping("/in-queue")
  @PreAuthorize("hasAnyRole('DOCTOR')")
  public List<TestRequest> getForConsultations() {
    return testRequestQueryService.findBy(RequestStatus.LAB_TEST_COMPLETED);
  }

  @GetMapping
  @PreAuthorize("hasAnyRole('DOCTOR')")
  public List<TestRequest> getForDoctor() {
    // Get logged-in doctor information
    User doctor = userLoggedInService.getLoggedInUser();

    // Find all the consultations belong to logged-in doctor
    return testRequestQueryService.findByDoctor(doctor);
  }

  @PreAuthorize("hasAnyRole('DOCTOR')")
  @PutMapping("/assign/{id}")
  public TestRequest assignForConsultation(@PathVariable Long id) {
    try {
      // Get logged-in doctor information
      User doctor = userLoggedInService.getLoggedInUser();

      // Assign consultation to logged-in doctor
      return testRequestUpdateService.assignForConsultation(id, doctor);
    } catch (AppException e) {
      log.error("Assign Consultation", e.getMessage(), e);
      throw asBadRequest(e.getMessage());
    }
  }

  @PreAuthorize("hasAnyRole('DOCTOR')")
  @PutMapping("/update/{id}")
  public TestRequest updateConsultation(
      @PathVariable Long id, @RequestBody CreateConsultationRequest testResult) {
    try {
      // Get logged-in doctor information
      User doctor = userLoggedInService.getLoggedInUser();

      // Update consultation
      return testRequestUpdateService.updateConsultation(id, testResult, doctor);
    } catch (ConstraintViolationException e) {
      log.error("Update Consultation", e.getMessage(), e);
      throw asConstraintViolation(e);
    } catch (AppException e) {
      log.error("Update Consultation", e.getMessage(), e);
      throw asBadRequest(e.getMessage());
    }
  }
}
