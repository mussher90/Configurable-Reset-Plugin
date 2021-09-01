<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
	<#if section = "header">
		${msg("forgottenPasswordTitle",realm.displayName)}
	<#elseif section = "form">
		<form id="kc-extended-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
			<div class="${properties.kcFormGroupClass!}">
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="username" class="${properties.kcLabelClass!}">${msg("forgottenPasswordUsernameLabel")}</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<input type="text" id="username" name="username" class="${properties.kcInputClass!}" autofocus/>
				</div>
			<#if emailRequired??>
				<div class="${properties.kcLabelWrapperClass!}">
                	<label for="email" class="${properties.kcLabelClass!}">${msg("forgottenPasswordEmailLabel")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                	<input type="text" id="email" name="email" class="${properties.kcInputClass!}"/>
                </div>
            </#if>
            <#if phoneNumberRequired??>
                <div class="${properties.kcLabelWrapperClass!}">
                     <label for="phoneNumber" class="${properties.kcLabelClass!}">${msg("forgottenPasswordPhoneNumberLabel")}</label>
                </div>
                 <div class="${properties.kcInputWrapperClass!}">
                      <input type="text" id="phoneNumber" name="phoneNumber" class="${properties.kcInputClass!}"/>
                 </div>
            </#if>

                        <#if recaptchaRequired??>
                            <div class="form-group">
                                <div class="${properties.kcInputWrapperClass!}">
                                    <div class="g-recaptcha" data-size="compact" data-sitekey="${recaptchaSiteKey}"></div>
                                </div>
                            </div>
                        </#if>

			</div>
			<div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
				<div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
					<div class="${properties.kcFormOptionsWrapperClass!}">
						<span><a href="${url.loginUrl}">${kcSanitize(msg("backToLogin"))?no_esc}</a></span>
					</div>
				</div>

				<div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
					<input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doSubmit")}"/>
				</div>
			</div>
		</form>
	<#elseif section = "info" >
		${msg("forgottenPasswordInstruction")}
	</#if>
</@layout.registrationLayout>

