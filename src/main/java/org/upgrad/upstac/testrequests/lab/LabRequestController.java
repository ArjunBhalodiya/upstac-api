package org.upgrad.upstac.testrequests.lab;

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
@RequestMapping("/api/labrequests")
public class LabRequestController {

  Logger log = LoggerFactory.getLogger(LabRequestController.class);

  @Autowired private TestRequestUpdateService testRequestUpdateService;

  @Autowired private TestRequestQueryService testRequestQueryService;

  @Autowired private UserLoggedInService userLoggedInService;

  @GetMapping("/to-be-tested")
  @PreAuthorize("hasAnyRole('TESTER')")
  public List<TestRequest> getForTests() {
    return testRequestQueryService.findBy(RequestStatus.INITIATED);
  }

  @GetMapping
  @PreAuthorize("hasAnyRole('TESTER')")
  public List<TestRequest> getForTester() {
    // Get logged-in tester information
    User tester = userLoggedInService.getLoggedInUser();

    // Find all the tests belong to logged-in tester
    return testRequestQueryService.findByTester(tester);
  }

  @PreAuthorize("hasAnyRole('TESTER')")
  @PutMapping("/assign/{id}")
  public TestRequest assignForLabTest(@PathVariable Long id) {
    try {
      // Get logged-in tester information
      User tester = userLoggedInService.getLoggedInUser();

      // Assign lab test to logged-in tester
      return testRequestUpdateService.assignForLabTest(id, tester);
    } catch (AppException e) {
      log.error("Assign Test Results", e.getMessage(), e);
      throw asBadRequest(e.getMessage());
    }
  }

  @PreAuthorize("hasAnyRole('TESTER')")
  @PutMapping("/update/{id}")
  public TestRequest updateLabTest(
      @PathVariable Long id, @RequestBody CreateLabResult createLabResult) {
    try {
      // Get logged-in tester information
      User tester = userLoggedInService.getLoggedInUser();

      // Update lab test
      return testRequestUpdateService.updateLabTest(id, createLabResult, tester);
    } catch (ConstraintViolationException e) {
      log.error("Update Test Results", e.getMessage(), e);
      throw asConstraintViolation(e);
    } catch (AppException e) {
      log.error("Update Test Results", e.getMessage(), e);
      throw asBadRequest(e.getMessage());
    }
  }
}
